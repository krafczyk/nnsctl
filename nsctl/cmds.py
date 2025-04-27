import os
import sys
import subprocess
import time
import psutil
import argparse
import shutil
from pprint import pprint
from dataclasses import dataclass
from typing import Annotated, cast
from autoparser import Arg, AddDataclassArguments, NamespaceToDataclass, DataclassType, Handler
from nsctl.config import load_namespace_config, ns_config_base_path, \
    save_namespace_config, Namespaces, NSInfo
from nsctl.processes import run, run_check, run_check_output, \
    find_bottom_children, process_exists, detach_and_check
from nsctl.utils import check_ops
from nsctl.network import get_active_ip_iface, is_ip_forwarding_enabled, \
    disable_ip_forwarding, disable_route_localnet
from nsctl import VERSION


@dataclass
class NSArgs:
    ns_name: Annotated[str, Arg(help="The name of the namespace")]

@dataclass
class DryRunArgs:
    dry_run: Annotated[bool, Arg("--dry-run", help="If passed report the commands that would be run but not execute them", action="store_true")]

@dataclass
class NSBasicArgs(NSArgs, DryRunArgs):
    pass


def net_init(args: NSBasicArgs):
    ns_config = load_namespace_config(args.ns_name)

    try:
        # Activate loopback device
        run_check(
            "ip set up lo",
            ns=ns_config,
            dry_run=args.dry_run,
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to set up loopback device: {e}")

    try:
        # create named net ns
        run_check(
            f"ip netns add {ns_config.name} /proc/{ns_config.pid}/ns/net",
            escalate="sudo",
            dry_run=args.dry_run,
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to create network namespace: {e}")


def net_init_dns_config(args: NSBasicArgs):
    ns_config = load_namespace_config(args.ns_name)
    if not ns_config.namespaces.mount:
        raise RuntimeError("No mount namespace found, it is required for custom dns conf.")

    dry_run = args.dry_run
    # Configure DNS for the namespace
    print("Configuring DNS for the namespace")
    ns_resolv_dir = f"/etc/netns/{ns_config.name}"
    run_check(
        f"mkdir -p {ns_resolv_dir}",
        dry_run=dry_run,
        escalate="sudo")
    run_check(
        f"cp /etc/resolv.conf {os.path.join(ns_resolv_dir, 'resolv.conf')}",
        dry_run=dry_run,
        escalate="sudo")


def net_remove_dns_config(
        args:NSBasicArgs):
    ns_config = load_namespace_config(args.ns_name)

    # Remove the DNS configuration for the namespace
    ns_resolv_dir = f"/etc/netns/{ns_config.name}"
    if os.path.exists(os.path.join(ns_resolv_dir, "resolv.conf")):
        run_check(
            ["rm", "-rf", ns_resolv_dir],
            dry_run=args.dry_run,
            escalate="sudo")


@dataclass
class NSRemoveArgs(NSArgs, DryRunArgs):
    pass


def net_remove(args: NSBasicArgs):
    ns_config = load_namespace_config(args.ns_name)
    if ns_config.namespaces.mount:
        net_remove_dns_config(args)

    # Check if the namespace is already removed
    netns_list = run_check_output(
        "ip netns list",
    )

    if ns_config.name not in netns_list:
        print(f"Namespace {ns_config.name} already removed.")
        return

    # destroy named net ns
    run_check(
        f"ip netns del {ns_config.name}",
        escalate="sudo",
        dry_run=args.dry_run,
    )


@dataclass
class NetAddMacvlanArgs(NSArgs):
    dev: Annotated[str, Arg("--dev", help="Name of device to use. Otherwise it will be macvlan0", default="mavlan0")]
    host_if: Annotated[str|None, Arg("--host-if", help="The host if to use, if not specified, a heuristic is used to find it instead.", required=False)]
    ip: Annotated[str|None, Arg("--ip", help="IP to assign, otherwise use dhclient (dhcp)", required=False, type=str)]

def net_add_macvlan(args: NetAddMacvlanArgs):
    ns_name = args.ns_name

    # Load the namespace configuration
    ns_config = load_namespace_config(ns_name)

    # Get the host interface
    host_iface = args.host_if
    if host_iface is None:
        host_iface = get_active_ip_iface()[0]

    print(f"Host iface to use: {host_iface}")

    # Create the macvlan interface
    macvlan_name = args.dev

    # Create the macvlan interface on the host
    run_check(
        f"ip link add link {host_iface} name {macvlan_name} type macvlan mode bridge",
        escalate="sudo")

    # Assign it to the net namespace
    run_check(
        f"ip link set {macvlan_name} netns {ns_config.name}",
        escalate="sudo")

    # # Use dhclient to get an IP address
    # # TODO: Make this more cross-platform
    # process = subprocess.Popen(
    #     cmd,
    #     stdout=subprocess.PIPE,
    #     stderr=subprocess.STDOUT,
    #     start_new_session=True, # Create a new session, detaching the process
    # )

    # # Wait for the process to start, and check that it didn't fail
    # time.sleep(1)
    # if process.poll() is not None:
    # run_in_namespace(
    #     ns_config,
    #     "dhclient "
    #         )


@dataclass
class NetRemoveMacvlanArgs(NSArgs):
    dev: Annotated[str, Arg("--dev", help="Name of device to use. Otherwise it will be macvlan0", default="mavlan0")]


def net_remove_macvlan(args: NetRemoveMacvlanArgs):
    ns_name = args.ns_name
    # Load the namespace configuration
    ns_config = load_namespace_config(ns_name)
    # Remove the macvlan interface
    macvlan_name = args.dev
    # Destroy the macvlan interface on the host
    run_check(
        f"ip netns exec {ns_config.name} ip link del {macvlan_name}",
        escalate="sudo")


@dataclass
class CreateNSArgs(NSArgs, DryRunArgs):
    net: Annotated[bool, Arg("--net", help="Create a network namespace")]
    mount: Annotated[bool, Arg("--mount", help="Create a mount namespace")]
    pid: Annotated[bool, Arg("--pid", help="Create a pid namespace")]
    ipc: Annotated[bool, Arg("--ipc", help="Create an ipc namespace")]
    uts: Annotated[bool, Arg("--uts", help="Create an uts namespace")]
    user: Annotated[bool, Arg("--user", help="Create an user namespace")]
    cgroup: Annotated[bool, Arg("--cgroup", help="Create an cgroup namespace")]
    time: Annotated[bool, Arg("--time", help="Create an time namespace")]
    all: Annotated[bool, Arg("--all", help="Create all namespaces")]
    sudo: Annotated[bool, Arg("--sudo", help="Use sudo to create the namespace")]

def create_namespace(args: CreateNSArgs) -> None:
    ns_name: str = args.ns_name

    # Set namespace creation flags
    net = args.net
    mount = args.mount
    pid = args.pid
    ipc = args.ipc
    uts = args.uts
    user = args.user
    cgroup = args.cgroup
    time_ns = args.time

    if args.all:
        net = True
        mount = True
        pid = True
        ipc = True
        uts = True
        user = True
        cgroup = True
        time_ns = True

    ns = Namespaces(
        net=net,
        mount=mount,
        pid=pid,
        ipc=ipc,
        uts=uts,
        user=user,
        cgroup=cgroup,
        time=time_ns,
    )

    # Check if the namespace already exists
    if os.path.exists(f"{ns_config_base_path}/{ns_name}"):
        print(f"Namespace {ns_name} already exists.")
        sys.exit(1)

    # Create the namespaces using unshare
    cmd = [ "unshare" ]
    if net:
        cmd += [ "--net" ]
    if mount:
        cmd += [ "--mount", "--propagation", "private" ]
    if pid:
        cmd += [ "--pid" ]
    if ipc:
        cmd += [ "--ipc" ]
    if uts:
        cmd += [ "--uts" ]
    if user:
        cmd += [ "--user" ]
    if cgroup:
        cmd += [ "--cgroup" ]
    if time_ns:
        cmd += [ "--time" ]

    cmd += [ "--fork", "sleep", "infinity" ]

    process = detach_and_check(
        cmd,
        escalate="sudo" if not check_ops(ns) else None,
        dry_run=args.dry_run,
        wait_time=1,
    )

    # Find the bottom-most children of the unshare process
    unshare_pid = process.pid
    sleeper_pid = find_bottom_children(unshare_pid)

    if len(sleeper_pid) == 0:
        raise RuntimeError("Trying to find sleeper for pid {unshare_pid} but found none.")
    if len(sleeper_pid) > 1:
        raise RuntimeError("Found more than one sleeper for pid {unshare_pid}.")
    sleeper_pid = sleeper_pid[0].pid

    # Verify the sleeper is the sleep process
    sleep_process = psutil.Process(sleeper_pid)
    if sleep_process.name() != "sleep":
        raise RuntimeError(f"Expected detected sleeper process at PID {sleeper_pid} to be 'sleep' but found {sleep_process.name()}. unshare PID was {unshare_pid}.")

    print(f"Namspaces created, Sleeper PID: {sleeper_pid}")

    # Create configuration data
    config = NSInfo(
        name=ns_name,
        pid=sleeper_pid,
        namespaces=ns
    )

    # Write configuration to file
    ns_config_path = os.path.join(ns_config_base_path, ns_name)
    if not os.path.exists(ns_config_path):
        os.makedirs(ns_config_path)

    save_namespace_config(ns_name, config=config)

    if net:
        net_init(NSBasicArgs(ns_name = config.name, dry_run=args.dry_run))

    if mount and net:
        net_init_dns_config(NSBasicArgs(ns_name = config.name, dry_run=args.dry_run))

    print(f"Created namespace {ns_name} with PID {unshare_pid}")


def show_namespace(args: NSArgs):
    ns_name: str = args.ns_name

    # Load the namespace configuration
    ns_config = load_namespace_config(ns_name)

    print(f"Namespace {ns_name}:")
    pprint(ns_config.model_dump())


def stat_ns(path: str) -> tuple[int,int]:
    """
    Return (st_dev, st_ino) for path. If os.stat() is denied, fall back to
    `sudo stat -Lc "%d %i" path` and parse its output.
    """
    try:
        st = os.stat(path)
        return (st.st_dev, st.st_ino)
    except PermissionError:
        # fallback to sudo stat
        try:
            out = subprocess.check_output(
                ["sudo", "stat", "-Lc", "%d %i", path],
                text=True,
                stderr=subprocess.DEVNULL
            ).strip()
            dev_str, ino_str = out.split()
            return (int(dev_str), int(ino_str))
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to sudo‑stat {path}: {e}") from e


def list_ns_entries(ns_dir: str):
    """
    Return a list of namespace entry names under ns_dir.
    If os.listdir() is denied, use `sudo ls -1 ns_dir` to get them.
    """
    try:
        return os.listdir(ns_dir)
    except PermissionError:
        out = subprocess.check_output(
            ["sudo", "ls", "-1", ns_dir],
            text=True,
            stderr=subprocess.DEVNULL
        )
        return [line for line in out.splitlines() if line]


def get_namespaced_pids(owner_pid: int) -> list[int]:
    """
    Return a list of all PIDs on the host that live in exactly the same
    set of namespaces as the given owner_pid. If the owner_pid doesn't
    exist, return an empty list.
    """
    owner_ns_dir = f'/proc/{owner_pid}/ns'
    if not os.path.isdir(owner_ns_dir):
        # No such process!
        return []

    # 1) Record (st_dev, st_ino) for each namespace of the owner
    owner_ns: dict[str,tuple[int,int]] = {}
    for ns_name in list_ns_entries(owner_ns_dir):
        if 'children' in ns_name:
            # Skip namespaces which have 'for_children' in the name.
            continue
        path = os.path.join(owner_ns_dir, ns_name)
        try:
            owner_ns[ns_name] = stat_ns(path)
        except Exception:
            continue

    if not owner_ns:
        raise RuntimeError(f"Could not read namespace info for PID {owner_pid}")

    matching_pids: list[int] = []
    # 2) Scan every numeric entry in /proc
    for entry in os.listdir('/proc'):
        if not entry.isdigit():
            continue
        pid = entry
        ns_dir = f'/proc/{pid}/ns'
        if not os.path.isdir(ns_dir):
            continue

        # 3) Compare each namespace inode+dev to the owner's
        for ns_name, (dev, ino) in owner_ns.items():
            other_path = os.path.join(ns_dir, ns_name)
            try:
                if stat_ns(other_path) != (dev, ino):
                    break;
            except Exception:
                break

        else:
            # all namespaces matched
            matching_pids.append(int(pid))

    return sorted(matching_pids)
 

@dataclass
class PSArgs(NSArgs):
    ps_args: Annotated[list[str], Arg(nargs=argparse.REMAINDER, help="Other arguments to pass to ps")]


def ps(args: PSArgs):
    ns_name: str = args.ns_name
    ps_args: list[str] = args.ps_args

    # Get the namespace configuration
    ns_config = load_namespace_config(ns_name)

    namespaced_pids = get_namespaced_pids(ns_config.pid)

    if not namespaced_pids:
        print("No processes found in namespace group {ns_name}.")
        return

    pid_list = ",".join(str(pid) for pid in namespaced_pids)

    cmd = ["ps", "-f"]
    if ps_args:
        cmd.extend(ps_args)
    cmd.extend(["-p", pid_list])

    _ = subprocess.run(cmd)


# def create_namespace_old(args):
#     ns_name = args.ns_name
#     host_ip = args.host_ip
#     host_if = args.host_if
#     ns_subnet = args.ns_subnet
#     dry_run = args.dry_run

#     # Assumption: ns_subnet should be like 192.168.2.0

#     # Auto-detect host interface and subnet if not provided
#     # TODO: Improve detection logic
#     if not host_if or not host_ip:
#         detected_if, detected_ip = get_active_ip_iface()
#         if not host_if:
#             host_if = detected_if
#         if not host_ip:
#             host_ip = detected_ip
#             # Use the first three octets as the subnet prefix (e.g. "192.168.1")
#             host_subnet = ".".join(host_ip.split('.')[:3])+".0"
#     else:
#         host_subnet = host_ip.split('.')[:3] + ".0"

#     # For ns_subnet, if not provided, generate one by incrementing the last octet of host_subnet
#     # TODO: Make this more robust
#     if not ns_subnet:
#         parts = host_subnet.split('.')
#         it = int(parts[-2])
#         it = (it + 1) % 255
#         parts[-2] = str(it)
#         ns_subnet = ".".join(parts)

#     ns_subnet_triplet = '.'.join(ns_subnet.split('.')[:3])

#     # Define veth names and assign IP addresses
#     host_veth = f"{ns_name}0"
#     ns_veth = f"{ns_name}1"
#     host_veth_ip_addr = f"{ns_subnet_triplet}.1"
#     ns_veth_ip_addr = f"{ns_subnet_triplet}.2"

#     # Check if namespace already exists
#     existing = run_cmd("ip netns list", capture_output=True).stdout
#     if ns_name in existing:
#         print(f"Namespace {ns_name} already exists.")
#         sys.exit(1)

#     # Create configuration directory and file
#     config_dir = f"{ns_config_base_path}/{ns_name}"
#     config_file = os.path.join(config_dir, "configuration.conf")
#     if not dry_run:
#         os.makedirs(config_dir, exist_ok=True)
#     else:
#         print(f"Would create directory {config_dir}")

#     print(f"Creating network namespace {ns_name}")
#     run_cmd_sudo(f"ip netns add {ns_name}", dry_run=dry_run)
#     print(f"Creating veth pair {host_veth} <-> {ns_veth}")
#     run_cmd_sudo(f"ip link add {host_veth} type veth peer name {ns_veth}", dry_run=dry_run)
#     print(f"Moving {ns_veth} into namespace {ns_name}")
#     run_cmd_sudo(f"ip link set {ns_veth} netns {ns_name}", dry_run=dry_run)

#     print("Configuring IP addresses and interfaces")
#     # Assigning IP addresses
#     run_cmd_sudo(f"ip addr add {host_veth_ip_addr}/24 dev {host_veth}", dry_run=dry_run)
#     run_cmd_sudo(f"ip netns exec {ns_name} ip addr add {ns_veth_ip_addr}/24 dev {ns_veth}", dry_run=dry_run)

#     # Bring up the interfaces
#     run_cmd_sudo(f"ip link set {host_veth} up", dry_run=dry_run)
#     run_cmd_sudo(f"ip netns exec {ns_name} ip link set {ns_veth} up", dry_run=dry_run)
#     run_cmd_sudo(f"ip netns exec {ns_name} ip link set lo up", dry_run=dry_run)

#     # Set default route within the namespace
#     run_cmd_sudo(f"ip netns exec {ns_name} ip route add default via {host_veth_ip_addr}", dry_run=dry_run)

#     print("Enabling IP forwarding")
#     enable_ip_forwarding(dry_run=dry_run)

#     # Use provided host_ip if given; otherwise, auto-detect
#     if args.host_ip:
#         host_ip = args.host_ip
#     else:
#         _, detected_ip = get_active_ip_iface()
#         host_ip = detected_ip

#     print("Setting iptables routing rules")
#     run_cmd_sudo(f"iptables -I FORWARD -i {host_veth} -o {host_if} -j ACCEPT")
#     run_cmd_sudo(f"iptables -I FORWARD -i {host_if} -o {host_veth} -m state --state RELATED,ESTABLISHED -j ACCEPT")
#     run_cmd_sudo(f"iptables -t nat -A POSTROUTING -s {ns_subnet}/24 -o {host_if} -j MASQUERADE", dry_run=dry_run)

#     # Allow forwarding from the namespace veth to the loopback interface, useful for port forwarding
#     run_cmd_sudo(f"iptables -A FORWARD -i lo -o {host_veth} -m state --state RELATED,ESTABLISHED -j ACCEPT")


#     config_data = {
#         "ns_name": ns_name,
#         "host_veth": host_veth,
#         "ns_veth": ns_veth,
#         "host_veth_ip_addr": host_veth_ip_addr,
#         "ns_veth_ip_addr": ns_veth_ip_addr,
#         "host_if": host_if,
#         "host_ip": host_ip,
#         "host_subnet": host_subnet,
#         "ns_subnet": ns_subnet,
#     }

#     # Save the configuration to file for later use
#     if not dry_run:
#         with open(config_file, "w") as f:
#             f.write(json.dumps(config_data))
#         print(f"Namespace {ns_name} created with configuration saved in {config_file}")
#     else:
#         print(f"Would write the following to {config_file}")
#         pprint(config_data)


@dataclass
class DestroyNSArgs(NSArgs, DryRunArgs):
    force: Annotated[bool, Arg(help="Force kill running processes in the namespace")]
    sudo: Annotated[bool, Arg(help="Use sudo to kill processes.")]


def destroy_namespace(args: DestroyNSArgs):
    ns_name = args.ns_name
    force = args.force
    escalate: str|None

    if args.sudo:
        escalate = "sudo"
    else:
        escalate = None

    # Get the namespace configuration
    ns_config = load_namespace_config(ns_name)
    print(f"Destroying network namespace {ns_name}")

    if ns_config.namespaces.net:
        # Remove the network namespace links
        net_remove(NSBasicArgs(ns_name=ns_config.name, dry_run=args.dry_run))

    print(f"Seeing if there are still processes in the namespace {ns_name}")
    owner_pid = ns_config.pid

    namespaced_pids = get_namespaced_pids(owner_pid)
    pids = [ p for p in namespaced_pids if p != owner_pid ]

    def prune_processes(pids: list[int]) -> list[int]:
        """Prune processes that are no longer running"""
        return [p for p in pids if process_exists(p)]

    if pids and not force:
        print("The following processes are still running in the namespace:")
        for pid in pids:
            print(pid)
        print("Use --force to kill these processes and proceed with destroying the namespace.")
        sys.exit(1)

    elif pids and force:
        print("Killing processes in the namespace:")
        run_check(["kill", "-TERM"]+list(map(str, pids)), escalate=escalate, dry_run=args.dry_run)
        time.sleep(5)
        pids = prune_processes(pids)
        if pids:
            run_check(["kill", "-KILL"]+list(map(str,pids)), escalate=escalate, dry_run=args.dry_run)
        time.sleep(5)
        pids = prune_processes(pids)
        if pids:
            raise RuntimeError(f"Failed to kill processes in namespace {ns_name}. Some processes are still running: {pids}")

    if process_exists(owner_pid):
        # Delete the namespace
        run_check(["kill", "-TERM", str(owner_pid)], escalate=escalate, dry_run=args.dry_run)
        time.sleep(5)
        if process_exists(owner_pid):
            run_check(["kill", "-KILL", str(owner_pid)], escalate=escalate, dry_run=args.dry_run)
        time.sleep(5)
        if process_exists(owner_pid):
            raise RuntimeError(f"Failed to kill the namespace process {owner_pid}. It is still running.")
        print(f"Namespace {ns_name} destroyed.")

    # # Remove the DNS configuration for the namespace
    # ns_resolv_dir = f"/etc/netns/{ns_name}"
    # if os.path.exists(os.path.join(ns_resolv_dir, "resolv.conf")):
    #     run_cmd_sudo(["rm", "-rf", ns_resolv_dir])

    # Load configuration for the namespace
    config_dir = f"{ns_config_base_path}/{ns_name}"
    if os.path.exists(config_dir):
        shutil.rmtree(config_dir, ignore_errors=True)
        print(f"Configuration directory {config_dir} removed.")

    # Check if any other managed namespaces exist
    if os.path.exists(ns_config_base_path):
        remaining_namespaces = os.listdir(ns_config_base_path)
        if not remaining_namespaces:
            # Turn off IP forwarding if no other namespaces exist
            if is_ip_forwarding_enabled():
                disable_ip_forwarding()
                print("IP forwarding disabled as no other namespaces exist.")
            # Turn off route_localnet for the host lo interface just in case
            disable_route_localnet("lo")


# def status_namespace(args: NSArgs):
#     ns_name = args.ns_name
#     existing = run_cmd(["ip", "netns", "list"], capture_output=True).stdout

#     if ns_name is None:
#         print("Host Status:")
#         print("IP Addresses")
#         run_cmd("ip addr show")
#         print("Routes")
#         run_cmd("ip route show")
#         print("IPTables")
#         run_cmd_sudo("iptables -S")
#         print("IPTables NAT")
#         run_cmd_sudo("iptables -t nat -S")
#         sys.exit(0)

#     if ns_name not in existing:
#         print(f"Namespace {ns_name} does not exist.")
#         sys.exit(1)

#     print(f"Namespace {ns_name}:")
#     print("IP Addresses")
#     run_cmd_sudo(f"ip netns exec {ns_name} ip addr show")
#     print("Routes")
#     run_cmd_sudo(f"ip netns exec {ns_name} ip route show")
#     print("IPTables")
#     run_cmd_sudo(f"ip netns exec {ns_name} iptables -S")
#     print("IPTables NAT")
#     run_cmd_sudo(f"ip netns exec {ns_name} iptables -t nat -S")

#     config_file = f"{ns_config_base_path}/{ns_name}/configuration.conf"
#     namespace_config = load_namespace_config(ns_name)
#     if namespace_config is not None:
#         pprint(namespace_config)


@dataclass
class ExecArgs(NSArgs, DryRunArgs):
    as_user: Annotated[str, Arg("--as-user", help="Use sudo -u to execute the command as your user inside the namespace", default="nobody")]
    command: Annotated[list[str], Arg(nargs=argparse.REMAINDER, help="Command to execute")]


def exec_in_namespace(args: ExecArgs):
    if not args.command:
        print("No command specified for exec.")
        sys.exit(1)

    # only pass a real as_user if they explicitly asked for one
    as_user = None if args.as_user == "nobody" else args.as_user

    ns_config = load_namespace_config(args.ns_name)

    run(
        args.command,
        ns=ns_config,
        as_user=as_user,
        dry_run=args.dry_run)


#def port_forward_add(args):
#    ns_name = args.ns_name
#    port = args.port
#    namespace_config = load_namespace_config(ns_name)
#    if namespace_config is None:
#        print("Namespace not managed by nsctl.")
#        sys.exit(1)
#    host_veth_ip_addr = namespace_config["host_veth_ip_addr"]
#    ns_veth_ip_addr = namespace_config["ns_veth_ip_addr"]
#    host_veth = namespace_config["host_veth"]
#    ns_veth = namespace_config["ns_veth"]
#    print(f"Forwarding port {port}")
#    ## Rules inside the namespace (explanation from Gemini)
#    run_cmd(f"sudo ip netns exec {ns_name} iptables -t nat -A OUTPUT -p tcp -d 127.0.0.1 --dport {port} -j DNAT --to-destination {host_veth_ip_addr}")
#    run_cmd(f"sudo ip netns exec {ns_name} iptables -t nat -A POSTROUTING -o {ns_veth} -s 127.0.0.1 -d {host_veth_ip_addr} -p tcp --dport {port} -j SNAT --to-source {ns_veth_ip_addr}")
#    ## Rules inside the host namespace
#    run_cmd(f"sudo iptables -A FORWARD -i {host_veth} -o lo -p tcp  -d 127.0.0.1 --dport {port} -j ACCEPT")
#    run_cmd(f"sudo iptables -t nat -A PREROUTING -i {host_veth} -p tcp --dport {port} -j DNAT --to-destination 127.0.0.1")
#    run_cmd(f"sudo iptables -t nat -A POSTROUTING -o lo -p tcp -d 127.0.0.1 --dport {port} -s {ns_veth_ip_addr} -j SNAT --to-source 127.0.0.1")
#    print("Port forwarding rules added.")
#    enable_route_localnet(host_veth)
#    print(f"Enabled route_localnet for host interface {host_veth}.")


#def port_forward_del(args):
#    ns_name = args.ns_name
#    port = args.port
#    namespace_config = load_namespace_config(ns_name)
#    if namespace_config is None:
#        print("Namespace not managed by nsctl.")
#        sys.exit(1)
#    host_veth_ip_addr = namespace_config["host_veth_ip_addr"]
#    ns_veth_ip_addr = namespace_config["ns_veth_ip_addr"]
#    host_veth = namespace_config["host_veth"]
#    ns_veth = namespace_config["ns_veth"]
#    run_cmd(f"sudo ip netns exec {ns_name} iptables -t nat -D OUTPUT -p tcp -d 127.0.0.1 --dport {port} -j DNAT --to-destination {host_veth_ip_addr}", skip_error=True)
#    run_cmd(f"sudo ip netns exec {ns_name} iptables -t nat -D POSTROUTING -o {ns_veth} -s 127.0.0.1 -d {host_veth_ip_addr} -p tcp --dport {port} -j SNAT --to-source {ns_veth_ip_addr}", skip_error=True)
#    ## Rules inside the host namespace
#    run_cmd(f"sudo iptables -D FORWARD -i {host_veth} -o lo -p tcp  -d 127.0.0.1 --dport {port} -j ACCEPT", skip_error=True)
#    run_cmd(f"sudo iptables -t nat -D PREROUTING -i {host_veth} -p tcp --dport {port} -j DNAT --to-destination 127.0.0.1", skip_error=True)
#    run_cmd(f"sudo iptables -t nat -D POSTROUTING -o lo -p tcp -d 127.0.0.1 --dport {port} -s {ns_veth_ip_addr} -j SNAT --to-source 127.0.0.1", skip_error=True)
#    print(f"Port forwarding rules for port {port} removed.")

#x_ports_1 = "6000:6100"
#x_ports_2 = "6000-6100"

#def x_forward_add(args):
#    ns_name = args.ns_name
#    namespace_config = load_namespace_config(ns_name)
#    if namespace_config is None:
#        print("Namespace not managed by nsctl.")
#        sys.exit(1)
#    host_veth_ip_addr = namespace_config["host_veth_ip_addr"]
#    ns_veth_ip_addr = namespace_config["ns_veth_ip_addr"]
#    host_veth = namespace_config["host_veth"]
#    ns_veth = namespace_config["ns_veth"]
#    print(f"Forwarding ports {x_ports_2} (Likely to be used by X server) for namespace {ns_name}")
#    ## Rules inside the namespace (explanation from Gemini)
#    # Use the OUTPUT chain for locally generated packets
#    # Use DNAT to change the destination IP from localhost to the host's veth IP
#    run_cmd(f"sudo ip netns exec {ns_name} iptables -t nat -A OUTPUT -p tcp -d 127.0.0.1 --dport {x_ports_1} -j DNAT --to-destination {host_veth_ip_addr}")
#    # Avoid martian source errors by changing the source IP to the namespace's veth IP
#    run_cmd(f"sudo ip netns exec {ns_name} iptables -t nat -A POSTROUTING -o {ns_veth} -s 127.0.0.1 -d {host_veth_ip_addr} -p tcp --dport {x_ports_1} -j SNAT --to-source {ns_veth_ip_addr}")
#    ## Rules inside the host namespace
#    # Allow forwarding from the namespace veth to the loopback interface for X ports
#    run_cmd(f"sudo iptables -A FORWARD -i {host_veth} -o lo -p tcp  -d 127.0.0.1 --dport {x_ports_1} -j ACCEPT")
#    # PREROUTING (DNAT): Change destination IP from veth-host IP to localhost
#    # Intercepts packets arriving on veth-host for itself on X ports
#    run_cmd(f"sudo iptables -t nat -A PREROUTING -i {host_veth} -p tcp --dport {x_ports_1} -j DNAT --to-destination 127.0.0.1")
#    # POSTROUTING (SNAT): Change source IP to localhost (for xauth)
#    # For packets going *to* the loopback interface for X ports, change their source IP
#    # This helps satisfy xauth checks expecting connections from localhost
#    run_cmd(f"sudo iptables -t nat -A POSTROUTING -o lo -p tcp -d 127.0.0.1 --dport {x_ports_1} -s {ns_veth_ip_addr} -j SNAT --to-source 127.0.0.1")
#    print("Port forwarding rules added.")
#    enable_route_localnet(host_veth)
#    #enable_route_localnet("lo")
#    #enable_route_localnet(ns_veth, ns_name=ns_name)
#    #enable_route_localnet("lo", ns_name=ns_name)
#    print(f"Enabled route_localnet for host interface {host_veth}.")


#def x_forward_del(args):
#    ns_name = args.ns_name
#    namespace_config = load_namespace_config(ns_name)
#    if namespace_config is None:
#        print("Namespace not managed by nsctl.")
#        sys.exit(1)
#    host_veth_ip_addr = namespace_config["host_veth_ip_addr"]
#    ns_veth_ip_addr = namespace_config["ns_veth_ip_addr"]
#    host_veth = namespace_config["host_veth"]
#    ns_veth = namespace_config["ns_veth"]
#    # Remove the rules in the namespace
#    run_cmd(f"sudo ip netns exec {ns_name} iptables -t nat -D OUTPUT -p tcp -d 127.0.0.1 --dport {x_ports_1} -j DNAT --to-destination {host_veth_ip_addr}", skip_error=True)
#    run_cmd(f"sudo ip netns exec {ns_name} iptables -t nat -D POSTROUTING -o {ns_veth} -s 127.0.0.1 -d {host_veth_ip_addr} -p tcp --dport {x_ports_1} -j SNAT --to-source {ns_veth_ip_addr}", skip_error=True)
#    # Remove the rules in the host namespace
#    run_cmd(f"sudo iptables -D FORWARD -i {host_veth} -o lo -p tcp  -d 127.0.0.1 --dport {x_ports_1} -j ACCEPT", skip_error=True)
#    run_cmd(f"sudo iptables -t nat -D PREROUTING -i {host_veth} -p tcp --dport {x_ports_1} -j DNAT --to-destination 127.0.0.1", skip_error=True)
#    run_cmd(f"sudo iptables -t nat -D POSTROUTING -o lo -p tcp -d 127.0.0.1 --dport {x_ports_1} -s {ns_veth_ip_addr} -j SNAT --to-source 127.0.0.1", skip_error=True)

#    print(f"Port forwarding rules for ports {x_ports_2} removed.")


def list_namespaces(_: argparse.Namespace):
    # We list namespaces that have a configuration file under ns_config_base_path.
    if os.path.exists(ns_config_base_path):
        namespaces = os.listdir(ns_config_base_path)
        if namespaces:
            print("Listing Namespace groups managed by nsctl:")
            for ns in namespaces:
                print(ns)
            return
    print("No namespaces groups found.")


def currently_not_implemented(_: argparse.Namespace):
    raise NotImplementedError("This command is not implemented yet.")


def main():
    parser: argparse.ArgumentParser = argparse.ArgumentParser(prog="nsctl", description="Namespace group control tool")
    _ = parser.add_argument("--version", action="version", version=f"nsctl {VERSION}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # list command
    parser_list = subparsers.add_parser("list", help="List namespace groups managed by nsctl")
    parser_list.set_defaults(func=list_namespaces)

    # create command
    parser_create = subparsers.add_parser("create", help="Create a new namespace group")
    AddDataclassArguments(parser_create, CreateNSArgs)
    parser_create.set_defaults(func=create_namespace, arg_cls=CreateNSArgs)

    # show command
    parser_show = subparsers.add_parser("show", help="Show information about a particular namespace group")
    AddDataclassArguments(parser_show, NSArgs)
    parser_show.set_defaults(func=show_namespace, arg_cls=NSArgs)

    # destroy command
    parser_destroy = subparsers.add_parser("destroy", help="Destroy a namespace group")
    AddDataclassArguments(parser_destroy, DestroyNSArgs)
    parser_destroy.set_defaults(func=destroy_namespace, arg_cls=DestroyNSArgs)

    ### status command
    ##parser_status = subparsers.add_parser("status", help="Get status of a network namespace")
    ##parser_status.add_argument("ns_name", nargs="?", help=ns_name_help)
    ###parser_status.set_defaults(func=status_namespace)
    ##parser_status.set_defaults(func=currently_not_implemented)

    # ps command
    parser_ps = subparsers.add_parser("ps", help="Perform a ps on programs in a specific namespace")
    AddDataclassArguments(parser_ps, PSArgs)
    parser_ps.set_defaults(func=ps, arg_cls=PSArgs)

    # exec command
    parser_exec = subparsers.add_parser("exec", help="Execute a command inside a grouped namespace")
    AddDataclassArguments(parser_exec, ExecArgs)
    parser_exec.set_defaults(func=exec_in_namespace, arg_cls=ExecArgs)

    # net command
    parser_net = subparsers.add_parser("net", help="Execute a network namespace operation")
    subparsers_net = parser_net.add_subparsers(dest="subcommand", required=True)

    ### net init command
    ##parser_net_init = subparsers_net.add_parser("init", help="Initialize networking component")
    ##add_dry_run(parser_net_init)
    ##parser_net_init.add_argument("ns_name", help=ns_name_help)
    ##parser_net_init.set_defaults(func=net_init)

    # net add command
    parser_net_add = subparsers_net.add_parser("add", help="Add a networking component")
    subparsers_net_add = parser_net_add.add_subparsers(dest="subsubcommand", required=True)

    # net add macvlan command
    parser_net_add_macvlan = subparsers_net_add.add_parser("macvlan", help="Add a macvlan component to the network namespace.")
    AddDataclassArguments(parser_net_add_macvlan, NetAddMacvlanArgs)
    parser_net_add_macvlan.set_defaults(func=net_add_macvlan, arg_cls=NetAddMacvlanArgs)

    # net del command
    parser_net_del = subparsers_net.add_parser("del", help="Remove a networking component")
    subparsers_net_del = parser_net_del.add_subparsers(dest="subsubcommand", required=True)

    parser_net_del_macvlan = subparsers_net_del.add_parser("macvlan", help="Remove a macvlan component from the network namespace.")
    parser_net_del_macvlan.set_defaults()

    ### port-forward command
    ##parser_port_forward = subparsers.add_parser("port-forward", help="Utilities for forwarding a port between host and namespace")
    ##port_forward_subparsers = parser_port_forward.add_subparsers(dest="subcommand", required=True)

    ### port-forward add command
    ##parser_port_forward_add = port_forward_subparsers.add_parser("add", help="Add port forwarding for a particular port")
    ##parser_port_forward_add.add_argument("ns_name", help=ns_name_help)
    ##parser_port_forward_add.add_argument("port", type=int, help="Port number to forward")
    ##add_dry_run(parser_port_forward_add)
    ###parser_port_forward_add.set_defaults(func=port_forward_add)
    ##parser_port_forward_add.set_defaults(func=currently_not_implemented)

    ### port-forward del command
    ##parser_port_forward_del = port_forward_subparsers.add_parser("del", help="Delete port forwarding for a particular port")
    ##parser_port_forward_del.add_argument("ns_name", help=ns_name_help)
    ##parser_port_forward_del.add_argument("port", type=int, help="Port number to forward")
    ##add_dry_run(parser_port_forward_del)
    ###parser_port_forward_del.set_defaults(func=port_forward_del)
    ##parser_port_forward_del.set_defaults(func=currently_not_implemented)

    ### x-forward command
    ##parser_x_forward = subparsers.add_parser("x-forward", help="Forward X server ports (6000:6100) from host to namespace")
    ##parser_x_forward_subparsers = parser_x_forward.add_subparsers(dest="subcommand", required=True)

    ### x-forward add command
    ##parser_x_forward_add = parser_x_forward_subparsers.add_parser("add", help="Add X server port forwarding")
    ##parser_x_forward_add.add_argument("ns_name", help=ns_name_help)
    ##add_dry_run(parser_x_forward_add)
    ###parser_x_forward_add.set_defaults(func=x_forward_add)
    ##parser_x_forward_add.set_defaults(func=currently_not_implemented)

    ### x-forward del command
    ##parser_x_forward_del = parser_x_forward_subparsers.add_parser("del", help="Delete X server port forwarding")
    ##parser_x_forward_del.add_argument("ns_name", help=ns_name_help)
    ##add_dry_run(parser_x_forward_del)
    ###parser_x_forward_del.set_defaults(func=x_forward_del)
    ##parser_x_forward_del.set_defaults(func=currently_not_implemented)

    args: argparse.Namespace = parser.parse_args()
    if hasattr(args, 'arg_cls'):
        cls = cast(type[DataclassType], args.arg_cls)
        func = cast(Handler[DataclassType],args.func)
        func(NamespaceToDataclass(args, cls))
    else:
        args.func(args) # pyright: ignore[reportAny]
