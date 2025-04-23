#!/usr/bin/env python3
import argparse
from dataclasses import dataclass
from autoparser import Arg, AddDataclassArguments, NamespaceToDataclass, Handler
import subprocess
import os
import sys
import time
import shutil
import psutil
from pprint import pprint
from pydantic import BaseModel, Field
from enum import IntEnum, unique
from typing import Literal, Annotated, Callable, Optional


VERSION = "0.1.0"


ns_config_base_path = "/tmp/nsctl"


# Grouped Namespace information for serialization
class Namespaces(BaseModel):
    net: bool
    mount: bool
    pid: bool
    ipc: bool
    uts: bool
    user: bool
    cgroup: bool
    time: bool


class NetMacvlan(BaseModel):
    kind: Literal["macvlan"]
    host_if: str
    name: str
    ip: str


class NetHostForward(BaseModel):
    kind: Literal["host_forward"]
    host_ip: str
    ns_ip: str
    port: str # Can be a range as well


NetItem = Annotated[
    NetMacvlan | NetHostForward,
    Field(discriminator="kind")
]


class NSInfo(BaseModel):
    name: str
    pid: int
    namespaces: Namespaces
    net: list[NetItem] = Field(default_factory=list)


# Classes for managing privileges
@unique
class Capability(IntEnum):
    CAP_CHOWN            = 0
    CAP_DAC_OVERRIDE     = 1
    # … (fill in 0–37 from linux/capability.h) …
    CAP_SYS_ADMIN        = 21
    CAP_NET_ADMIN        = 12
    # etc.

class Capabilities:
    """
    Parse /proc/self/status for CapInh, CapPrm, CapEff.
    Exposes .inheritable, .permitted, .effective as ints.
    """
    inheritable: int
    permitted: int
    effective: int

    def __init__(self, pid: int|None=None):
        if pid is None:
            pid =  os.getpid()
        self._read_status(pid)

    def _read_status(self, pid: int):
        path = f"/proc/{pid}/status"
        caps = {}
        with open(path) as f:
            for line in f:
                for field in ("CapInh:", "CapPrm:", "CapEff:"):
                    if line.startswith(field):
                        # hex string → int
                        caps[field] = int(line.split()[1], 16)
        self.inheritable = caps["CapInh:"]
        self.permitted   = caps["CapPrm:"]
        self.effective   = caps["CapEff:"]

    def has(self, cap: Capability, which: str = "effective") -> bool:
        """
        which ∈ {'inheritable','permitted','effective'}
        """
        mask: int = getattr(self, which)
        return bool(mask & (1 << cap))


# Required capabilities for each namespace operation
REQUIRED = {
    "netns":  [Capability.CAP_NET_ADMIN, Capability.CAP_SYS_ADMIN],
    "mntns":  [Capability.CAP_SYS_ADMIN],
    "pidns":  [Capability.CAP_SYS_ADMIN],
}

def check_ops(ops: list[str]) -> bool:
    caps = Capabilities()
    if os.geteuid() == 0:
        return True
    for op in ops:
        for req in REQUIRED[op]:
            if not caps.has(req):
                return False
    return True


def run_cmd(cmd: list[str] | str,
            capture_output: bool=False,
            shell: bool=False,
            dry_run: bool=False,
            skip_error: bool=False,
            try_sudo: bool=False
           ) -> None | subprocess.CompletedProcess[str]:
    """
    Runs a command, and if try_sudo=True and it fails with a permission error,
    retries exactly once with sudo.
    """
    # if it's a string but not using shell, split it
    if isinstance(cmd, str) and not shell:
        cmd = cmd.split()

    # dry run?
    if dry_run:
        printable = cmd if isinstance(cmd, str) else " ".join(cmd)
        print("DRY-RUN:", printable)
        return None

    try:
        return subprocess.run(
            cmd,
            capture_output=capture_output,
            text=True,
            check=True,
            shell=shell
        )

    except subprocess.CalledProcessError as e:
        if skip_error:
            print(f"Warning: Command failed with error: {e}", file=sys.stderr)
            return None

        # only consider sudo-retry if opted in and not running as root
        if try_sudo and os.geteuid() != 0:
            out = (e.stderr or "") + (e.stdout or "")
            if ("Permission denied" in out
                or "Operation not permitted" in out
                or e.returncode in (1, 126)
            ):
                # build the sudo command
                if shell:
                    base = cmd if isinstance(cmd, str) else " ".join(cmd)
                    sudo_cmd = f"sudo {base}"
                else:
                    sudo_cmd = ["sudo"] + (cmd if isinstance(cmd, list) else cmd.split())
                print(f"Retrying with sudo: {sudo_cmd}", file=sys.stderr)
                # retry once, but disable further sudo attempts
                return run_cmd(
                    sudo_cmd,
                    capture_output=capture_output,
                    shell=shell,
                    dry_run=dry_run,
                    skip_error=skip_error,
                    try_sudo=False
                )

        # still failed (or not a permission error)
        printable = cmd if isinstance(cmd, str) else " ".join(cmd)
        print(f"Error running command: {printable}", file=sys.stderr)
        print(e.stderr or e, file=sys.stderr)
        return None


def run_cmd_sudo(*args, **kwargs):
    return run_cmd(*args, try_sudo=True, **kwargs)


def run_in_namespace(
        pid: int,
        command: list[str]|str,
        *,
        net: bool = False,
        mount: bool = False,
        pid_ns: bool = False,
        ipc: bool = False,
        uts: bool = False,
        user_ns: bool = False,
        cgroup: bool = False,
        time_ns: bool = False,
        namespaces: Namespaces|None = None,
        as_user: str|None = None,
        dry_run: bool = False,
        working_dir: str|None = None,
    ) -> subprocess.CompletedProcess[str] | None:
    """
    Execute `command` inside the namespaces of the given `pid` via nsenter.
    
    Flags correspond to the nsenter options:
      net, mount, pid_ns, ipc, uts, user_ns, cgroup, time_ns.
    If `as_user` is provided (e.g. "matthew"), we ssh-u to that UID/GID
    inside the namespace (requires sudo). Otherwise, if you're root it'll
    just call nsenter directly.
    """
    # 1) build the list of nsenter flags
    ns_args: list[str] = []
    if namespaces is not None:
        net = namespaces.net or net
        mount = namespaces.mount or mount
        pid_ns = namespaces.pid or pid_ns
        ipc = namespaces.ipc or ipc
        uts = namespaces.uts or uts
        user_ns = namespaces.user or user_ns
        cgroup = namespaces.cgroup or cgroup
        time_ns = namespaces.time or time_ns
 
    if net:       ns_args.append("--net")
    if mount:     ns_args.append("--mount")
    if pid_ns:    ns_args.append("--pid")
    if ipc:       ns_args.append("--ipc")
    if uts:       ns_args.append("--uts")
    if user_ns:   ns_args.append("--user")
    if cgroup:    ns_args.append("--cgroup")
    if time_ns:   ns_args.append("--time")
    if working_dir:
        ns_args.append(f"--wd={working_dir}")

    base = ["nsenter", "-t", str(pid)] + ns_args

    cmd: list[str] = []

    if type(command) is str:
        cmd = command.strip().split()

    # 2) if we're root, just run it
    if os.geteuid() == 0:
        cmd = base + cmd
        return run_cmd(cmd, dry_run=dry_run)

    # 3) otherwise wrap in sudo
    sudo_cmd = base.copy()
    if as_user:
        # resolve uid/gid
        uid = run_cmd(["id", "-u", as_user], capture_output=True).stdout.strip()
        gid = run_cmd(["id", "-g", as_user], capture_output=True).stdout.strip()
        sudo_cmd += [f"--setuid={uid}", f"--setgid={gid}"]
    sudo_cmd += ["--"] + cmd
    return run_cmd_sudo(sudo_cmd, dry_run=dry_run)


def get_active_ip_iface() -> tuple[str, str]:
    """
    Get the active (non-loopback) interface and its IP.
    Uses 'ip route get 8.8.8.8' to determine the primary interface.
    """
    try:
        route_out = run_cmd("ip route get 8.8.8.8", capture_output=True).stdout
        # Example output: "8.8.8.8 via 192.168.1.1 dev eth0 src 192.168.1.100 ..."
        tokens = route_out.split()
        iface = tokens[tokens.index("dev") + 1]
        src_index = tokens.index("src") + 1
        ip_addr = tokens[src_index]
        return iface, ip_addr
    except Exception:
        print("No active non-loopback interface found.")
        sys.exit(1)


def load_namespace_config(ns_name: str) -> NSInfo:
    """Load the namespace configuration from the file. If it can't, it will throw an exception"""
    config_path = os.path.join(
        ns_config_base_path,
        ns_name,
        "configuration.conf"
    )

    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file for namespace {ns_name} not found at {config_path}")
    with open(config_path) as f:
        return NSInfo.model_validate_json(f.read())


def save_namespace_config(ns_name: str, config: NSInfo):
    config_path = os.path.join(
        ns_config_base_path,
        ns_name,
        "configuration.conf"
    )
    with open(config_path, "w") as f:
        _ = f.write(config.model_dump_json(indent=2))


def find_bottom_children(pid: int) -> list[psutil.Process]:
    """
    Recursively returns a list of all leaf (bottom-most) processes
    in the process tree rooted at `pid`.
    """
    try:
        process = psutil.Process(pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return []

    children = process.children()
    if not children:
        # This process has no children, so it's a bottom-most process
        return [process]

    # Otherwise, collect bottom-most children of each child
    bottom: list[psutil.Process] = []
    for child in children:
        bottom.extend(find_bottom_children(child.pid))
    return bottom

@dataclass
class NSArgs:
    ns_name: Annotated[str, Arg(help="The name of the namespace")]

@dataclass
class DryRunArgs:
    dry_run: Annotated[bool, Arg("--dry-run", help="If passed report the commands that would be run but not execute them", action="store_true")]

@dataclass
class NSInitArgs(NSArgs, DryRunArgs):
    pass


def net_init(args: NSInitArgs):
    ns_config = load_namespace_config(args.ns_name)

    # Activate loopback device
    _ = run_in_namespace(
        ns_config.pid,
        "ip set up lo",
        namespaces=ns_config.namespaces,
        dry_run=args.dry_run,
    )

    # create named net ns
    _ = run_cmd_sudo(
        f"ip netns add {ns_config.name} /proc/{ns_config.pid}/ns/net",
        dry_run=args.dry_run
    )


@dataclass
class NSRemoveArgs(NSArgs, DryRunArgs):
    pass


def net_remove(args: NSRemoveArgs):
    ns_config = load_namespace_config(args.ns_name)

    # destroy named net ns
    _ = run_cmd_sudo(
        f"ip netns del {ns_config.name}",
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
    _ = run_cmd_sudo(f"ip link add link {host_iface} name {macvlan_name} type macvlan mode bridge")

    # Assign it to the net namespace
    _ = run_cmd_sudo(f"ip link set {macvlan_name} netns {ns_config.name}")

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
    _ = run_cmd_sudo(f"ip netns exec {ns_config.name} ip link del {macvlan_name}")


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

    sudo = args.sudo
   
    if args.all:
        net = True
        mount = True
        pid = True
        ipc = True
        uts = True
        user = True
        cgroup = True
        time_ns = True

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

    if sudo:
        cmd = ["sudo"] + cmd

    if args.dry_run:
        print("Would try to create a namespace with the following command:")
        print(" ".join(cmd))
        return

    # TODO: Make this more cross-platform
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True, # Create a new session, detaching the process
    )

    # Wait for the process to start, and check that it didn't fail
    time.sleep(1)
    if process.poll() is not None:
        if process.stdout is None:
            raise RuntimeError("unshare failed: stdout is None")
        output = process.stdout.read().decode(encoding='utf-8')
        if "unshare failed: Operation not permitted" in output:
            raise RuntimeError("unshare failed: Operation not permitted. This may be due to missing capabilities.")
        else:
            raise RuntimeError(f"Failed to create namespace with unshare. It unexpectedly exited. Ouptut was:\n{output}")

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

    # Create configuration data
    config = NSInfo(
        name=ns_name,
        pid=sleeper_pid,
        namespaces=Namespaces(
            net=net,
            mount=mount,
            pid=pid,
            ipc=ipc,
            uts=uts,
            user=user,
            cgroup=cgroup,
            time=time_ns,
        )
    )

    # Write configuration to file
    ns_config_path = os.path.join(ns_config_base_path, ns_name)
    if not os.path.exists(ns_config_path):
        os.makedirs(ns_config_path)

    save_namespace_config(ns_name, config=config)

    if net:
        net_init(NSInitArgs(ns_name = config.name, dry_run=args.dry_run))

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

#     print("Configuring DNS for the namespace")
#     ns_resolv_dir = f"/etc/netns/{ns_name}"
#     run_cmd_sudo(f"mkdir -p {ns_resolv_dir}", dry_run=dry_run)
#     run_cmd_sudo(f"cp /etc/resolv.conf {os.path.join(ns_resolv_dir, 'resolv.conf')}", dry_run=dry_run)

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


def scrub_routes(subnet: str):
    print("Checking host routes...")
    routes = run_cmd("ip route show", capture_output=True).stdout
    subnet_triplet = '.'.join(subnet.split('.')[:3])
    print(f"scrub triplet: {subnet_triplet}")
    if not routes:
        print("no routes found.")
        return
    for line in routes.splitlines():
        if subnet_triplet in line:
            print(f"Removing route: {line}")
            # Remove the route by reusing the route specification.
            # This may fail if additional fields cause mismatches, so you might need to adjust the parsing.
            _ = run_cmd_sudo(["ip", "route", "del"] + line.split())


def scrub_iptables_rules(subnet: str, iface: str):
    print("Checking iptables NAT rules...")
    subnet_triplet = '.'.join(subnet.split('.')[:3])
    print(f"scrub triplet: {subnet_triplet}")
    rules = run_cmd_sudo(["iptables", "-t", "nat", "-S"], capture_output=True).stdout
    if rules:
        for rule in rules.splitlines():
            # Check if the rule contains our problematic subnet
            if subnet_triplet in rule:
                # We only want to delte rules that were added (lines starting with "-A")
                if rule.startswith("-A"):
                    delete_rule = rule.replace("-A", "-D", 1)
                    cmd = ["iptables", "-t", "nat"] + delete_rule.split()
                    print(f"Deleting iptables NAT rule: {delete_rule}")
                    _ = run_cmd_sudo(cmd)

    print("Checking iptables routing rules...")
    rules = run_cmd_sudo(["iptables", "-S"], capture_output=True).stdout
    if rules:
        for rule in rules.splitlines():
            # Check if the rule contains our problematic subnet
            if iface in rule:
                # We only want to delte rules that were added (lines starting with "-A")
                if rule.startswith("-A"):
                    delete_rule = rule.replace("-A", "-D", 1)
                    cmd = ["iptables" ] + delete_rule.split()
                    print(f"Deleting iptables routing rule: {delete_rule}")
                    _ = run_cmd_sudo(cmd)


def is_ip_forwarding_enabled() -> bool:
    if os.path.exists("/proc/sys/net/ipv4/ip_forward"):
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            return f.read().strip() == "1"
    return False


def enable_route_localnet(iface: str, ns_name: str|None=None, dry_run:bool=False):
    if ns_name is None:
        _ = run_cmd_sudo(f"sysctl -w net.ipv4.conf.{iface}.route_localnet=1", dry_run=dry_run)
    else:
        _ = run_cmd_sudo(f"ip netns exec {ns_name} sysctl -w net.ipv4.conf.{iface}.route_localnet=1", dry_run=dry_run)


def disable_route_localnet(iface: str , ns_name: str|None=None, dry_run:bool=False):
    if ns_name is None:
        _ = run_cmd_sudo(f"sysctl -w net.ipv4.conf.{iface}.route_localnet=0", dry_run=dry_run)
    else:
        _ = run_cmd_sudo(f"ip netns exec {ns_name} sysctl -w net.ipv4.conf.{iface}.route_localnet=0", dry_run=dry_run)


def enable_ip_forwarding(dry_run:bool=False):
    _ = run_cmd_sudo("sysctl -w net.ipv4.ip_forward=1", dry_run=dry_run)


def disable_ip_forwarding(dry_run:bool=False):
    _ = run_cmd_sudo("sysctl -w net.ipv4.ip_forward=0", dry_run=dry_run)


def process_exists(pid: int):
    if os.path.exists(f"/proc/{pid}"):
        try:
            process = psutil.Process(pid)
            return process.is_running()
        except psutil.NoSuchProcess:
            return False


@dataclass
class DestroyNSArgs(NSArgs):
    force: Annotated[bool, Arg(help="Force kill running processes in the namespace")]


def destroy_namespace(args: DestroyNSArgs):
    ns_name = args.ns_name
    force = args.force

    # Get the namespace configuration
    ns_config = load_namespace_config(ns_name)
    print(f"Destroying network namespace {ns_name}")

    if ns_config.namespaces.net:
        # Remove the network namespace links
        net_remove(NSRemoveArgs(ns_name=ns_config.name, dry_run=False))

    print(f"Seeing if there are still processes in the namespace {ns_name}")
    owner_pid = ns_config.pid

    namespaced_pids = get_namespaced_pids(owner_pid)
    pids = [ p for p in namespaced_pids if p != owner_pid ]

    if pids and not force:
        print("The following processes are still running in the namespace:")
        for pid in pids:
            print(pid)
        print("Use --force to kill these processes and proceed with destroying the namespace.")
        sys.exit(1)

    elif pids and force:
        print("Killing processes in the namespace:")
        for pid in pids:
            print(f"Killing PID {pid}")
            _ = run_cmd_sudo(["kill", "-TERM", str(pid)])
        time.sleep(5)
        for pid in pids:
            if process_exists(pid):
                _ = run_cmd_sudo(["kill", "-KILL", str(pid)])

    if process_exists(owner_pid):
        # Delete the namespace
        _ = run_cmd_sudo(["kill", "-TERM", str(owner_pid)])
        time.sleep(5)
        _ = run_cmd_sudo(["kill", "-KILL", str(owner_pid)])
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

    _ = run_in_namespace(
        pid=ns_config.pid,
        command=args.command,
        namespaces=ns_config.namespaces,
        as_user=as_user,
        dry_run=args.dry_run,
        working_dir=os.getcwd())


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
    print("Listing Namespace groups managed by nsctl:")
    # We list namespaces that have a configuration file under ns_config_base_path.
    if os.path.exists(ns_config_base_path):
        for ns in os.listdir(ns_config_base_path):
            print(ns)
    else:
        print("No namespaces groups found.")


def currently_not_implemented(_: argparse.Namespace):
    raise NotImplementedError("This command is not implemented yet.")


def main():
    parser: argparse.ArgumentParser = argparse.ArgumentParser(prog="nsctl", description="Namespace group control tool")
    _ = parser.add_argument("--version", action="version", version=f"nsctl {VERSION}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    ns_name_help = "Name of the namespace group"

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
        func: Callable[Handler,None] = args.func
        func(NamespaceToDataclass(args, args.arg_cls))
    else:
        args.func(args)

if __name__ == "__main__":
    main()
