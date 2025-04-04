#!/usr/bin/env python3
import argparse
import subprocess
import os
import sys
import time
import json
import shutil
from pprint import pprint


VERSION = "0.1.0"


def run_cmd(cmd, capture_output=False, shell=False, dry_run=False, skip_error=False):
    if type(cmd) is str and not shell:
        cmd = cmd.split()
    """Run a system command and optionally return its output."""
    try:
        if not dry_run:
            result = subprocess.run(cmd, capture_output=capture_output, text=True, check=True, shell=shell)
            return result.stdout if capture_output else None
        else:
            print(' '.join(cmd))
            return None
    except subprocess.CalledProcessError as e:
        if not skip_error:
            print(f"Error running command: {' '.join(cmd) if not shell else cmd}")
            sys.exit(1)
        else:
            return None


def get_active_ip_iface():
    """
    Get the active (non-loopback) interface and its IP.
    Uses 'ip route get 8.8.8.8' to determine the primary interface.
    """
    try:
        route_out = run_cmd("ip route get 8.8.8.8", capture_output=True)
        # Example output: "8.8.8.8 via 192.168.1.1 dev eth0 src 192.168.1.100 ..."
        tokens = route_out.split()
        iface = tokens[tokens.index("dev") + 1]
        src_index = tokens.index("src") + 1
        ip_addr = tokens[src_index]
        return iface, ip_addr
    except Exception:
        print("No active non-loopback interface found.")
        sys.exit(1)


def load_namespace_config(ns_name):
    config_file = f"/tmp/nnsctl/{ns_name}/configuration.conf"
    if not os.path.exists(config_file):
        return None
    with open(config_file) as f:
        return json.load(f)


def create_namespace(args):
    ns_name = args.ns_name
    host_ip = args.host_ip
    host_if = args.host_if
    ns_subnet = args.ns_subnet
    dry_run = args.dry_run

    # Assumption: ns_subnet should be like 192.168.2.0

    # Auto-detect host interface and subnet if not provided
    # TODO: Improve detection logic
    if not host_if or not host_ip:
        detected_if, detected_ip = get_active_ip_iface()
        if not host_if:
            host_if = detected_if
        if not host_ip:
            host_ip = detected_ip
            # Use the first three octets as the subnet prefix (e.g. "192.168.1")
            host_subnet = ".".join(host_ip.split('.')[:3])+".0"
    else:
        host_subnet = host_ip.split('.')[:3] + ".0"

    # For ns_subnet, if not provided, generate one by incrementing the last octet of host_subnet
    # TODO: Make this more robust
    if not ns_subnet:
        parts = host_subnet.split('.')
        it = int(parts[-2])
        it = (it + 1) % 255
        parts[-2] = str(it)
        ns_subnet = ".".join(parts)

    ns_subnet_triplet = '.'.join(ns_subnet.split('.')[:3])

    # Define veth names and assign IP addresses
    host_veth = f"{ns_name}0"
    ns_veth = f"{ns_name}1"
    host_veth_ip_addr = f"{ns_subnet_triplet}.1"
    ns_veth_ip_addr = f"{ns_subnet_triplet}.2"

    # Check if namespace already exists
    existing = run_cmd("ip netns list", capture_output=True)
    if ns_name in existing:
        print(f"Namespace {ns_name} already exists.")
        sys.exit(1)

    # Create configuration directory and file
    config_dir = f"/tmp/nnsctl/{ns_name}"
    config_file = os.path.join(config_dir, "configuration.conf")
    if not dry_run:
        os.makedirs(config_dir, exist_ok=True)
    else:
        print(f"Would create directory {config_dir}")

    print(f"Creating network namespace {ns_name}")
    run_cmd(f"sudo ip netns add {ns_name}", dry_run=dry_run)
    print(f"Creating veth pair {host_veth} <-> {ns_veth}")
    run_cmd(f"sudo ip link add {host_veth} type veth peer name {ns_veth}", dry_run=dry_run)
    print(f"Moving {ns_veth} into namespace {ns_name}")
    run_cmd(f"sudo ip link set {ns_veth} netns {ns_name}", dry_run=dry_run)

    print("Configuring IP addresses and interfaces")
    # Assigning IP addresses
    run_cmd(f"sudo ip addr add {host_veth_ip_addr}/24 dev {host_veth}", dry_run=dry_run)
    run_cmd(f"sudo ip netns exec {ns_name} ip addr add {ns_veth_ip_addr}/24 dev {ns_veth}", dry_run=dry_run)

    # Bring up the interfaces
    run_cmd(f"sudo ip link set {host_veth} up", dry_run=dry_run)
    run_cmd(f"sudo ip netns exec {ns_name} ip link set {ns_veth} up", dry_run=dry_run)
    run_cmd(f"sudo ip netns exec {ns_name} ip link set lo up", dry_run=dry_run)

    # Set default route within the namespace
    run_cmd(f"sudo ip netns exec {ns_name} ip route add default via {host_veth_ip_addr}", dry_run=dry_run)

    print("Enabling IP forwarding")
    enable_ip_forwarding(dry_run=dry_run)

    # Use provided host_ip if given; otherwise, auto-detect
    if args.host_ip:
        host_ip = args.host_ip
    else:
        _, detected_ip = get_active_ip_iface()
        host_ip = detected_ip

    print("Setting iptables routing rules")
    run_cmd(f"sudo iptables -I FORWARD -i {host_veth} -o {host_if} -j ACCEPT")
    run_cmd(f"sudo iptables -I FORWARD -i {host_if} -o {host_veth} -m state --state RELATED,ESTABLISHED -j ACCEPT")
    #run_cmd(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-i", host_veth, "-d", host_ip, "-j", "DNAT", "--to-destination", "127.0.0.1"], dry_run=dry_run)
    #run_cmd(["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", host_veth, "-s", "127.0.0.1", "-j", "SNAT", "--to-source", host_ip], dry_run=dry_run)
    run_cmd(f"sudo iptables -t nat -A POSTROUTING -s {ns_subnet}/24 -o {host_if} -j MASQUERADE", dry_run=dry_run)
    #run_cmd(["sudo", "iptables", "-A", "FORWARD", "-o", host_if, "-i", host_veth, "-j", "ACCEPT"], dry_run=dry_run)
    #run_cmd(["sudo", "iptables", "-A", "FORWARD", "-i", host_if, "-o", host_veth, "-j", "ACCEPT"], dry_run=dry_run)

    print("Configuring DNS for the namespace")
    ns_resolv_dir = f"/etc/netns/{ns_name}"
    run_cmd(f"sudo mkdir -p {ns_resolv_dir}", dry_run=dry_run)
    run_cmd(f"sudo cp /etc/resolv.conf {os.path.join(ns_resolv_dir, 'resolv.conf')}", dry_run=dry_run)

    config_data = {
        "ns_name": ns_name,
        "host_veth": host_veth,
        "ns_veth": ns_veth,
        "host_veth_ip_addr": host_veth_ip_addr,
        "ns_veth_ip_addr": ns_veth_ip_addr,
        "host_if": host_if,
        "host_ip": host_ip,
        "host_subnet": host_subnet,
        "ns_subnet": ns_subnet,
    }

    # Save the configuration to file for later use
    if not dry_run:
        with open(config_file, "w") as f:
            f.write(json.dumps(config_data))
        print(f"Namespace {ns_name} created with configuration saved in {config_file}")
    else:
        print(f"Would write the following to {config_file}")
        pprint(config_data)


def scrub_routes(subnet):
    print("Checking host routes...")
    routes = run_cmd("ip route show", capture_output=True)
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
            run_cmd(["sudo", "ip", "route", "del"] + line.split())


def scrub_iptables_rules(subnet, iface):
    print("Checking iptables NAT rules...")
    subnet_triplet = '.'.join(subnet.split('.')[:3])
    print(f"scrub triplet: {subnet_triplet}")
    rules = run_cmd(["sudo", "iptables", "-t", "nat", "-S"], capture_output=True)
    if rules:
        for rule in rules.splitlines():
            # Check if the rule contains our problematic subnet
            if subnet_triplet in rule:
                # We only want to delte rules that were added (lines starting with "-A")
                if rule.startswith("-A"):
                    delete_rule = rule.replace("-A", "-D", 1)
                    cmd = ["sudo", "iptables", "-t", "nat"] + delete_rule.split()
                    print(f"Deleting iptables NAT rule: {delete_rule}")
                    run_cmd(cmd)

    print("Checking iptables routing rules...")
    rules = run_cmd(["sudo", "iptables", "-S"], capture_output=True)
    if rules:
        for rule in rules.splitlines():
            # Check if the rule contains our problematic subnet
            if iface in rule:
                # We only want to delte rules that were added (lines starting with "-A")
                if rule.startswith("-A"):
                    delete_rule = rule.replace("-A", "-D", 1)
                    cmd = ["sudo", "iptables" ] + delete_rule.split()
                    print(f"Deleting iptables routing rule: {delete_rule}")
                    run_cmd(cmd)


def is_ip_forwarding_enabled() -> bool:
    if os.path.exists("/proc/sys/net/ipv4/ip_forward"):
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            return f.read().strip() == "1"
    return False


def enable_route_localnet(iface, ns_name=None, dry_run=False):
    if ns_name is None:
        run_cmd(f"sudo sysctl -w net.ipv4.conf.{iface}.route_localnet=1", dry_run=dry_run)
    else:
        run_cmd(f"sudo ip netns exec {ns_name} sysctl -w net.ipv4.conf.{iface}.route_localnet=1", dry_run=dry_run)


def disable_route_localnet(iface, ns_name=None, dry_run=False):
    if ns_name is None:
        run_cmd(f"sudo sysctl -w net.ipv4.conf.{iface}.route_localnet=0", dry_run=dry_run)
    else:
        run_cmd(f"sudo ip netns exec {ns_name} sysctl -w net.ipv4.conf.{iface}.route_localnet=0", dry_run=dry_run)


def enable_ip_forwarding(dry_run=False):
    run_cmd(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], dry_run=dry_run)


def disable_ip_forwarding(dry_run=False):
    run_cmd(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"], dry_run=dry_run)


def destroy_namespace(args):
    ns_name = args.ns_name
    force = args.force

    existing = run_cmd(["ip", "netns", "list"], capture_output=True)
    if ns_name in existing:
        print(f"Destroying network namespace {ns_name}")

        # Check for running processes inside the namespace
        pids_result = run_cmd(["sudo", "ip", "netns", "pids", ns_name], capture_output=True)
        pids = pids_result.strip().split()
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
                subprocess.run(["sudo", "kill", "-TERM", pid])
            time.sleep(5)
            for pid in pids:
                subprocess.run(["sudo", "kill", "-KILL", pid])

        # Delete the namespace
        run_cmd(["sudo", "ip", "netns", "del", ns_name])
        print(f"Namespace {ns_name} destroyed.")

    # Remove the DNS configuration for the namespace
    ns_resolv_dir = f"/etc/netns/{ns_name}"
    if os.path.exists(os.path.join(ns_resolv_dir, "resolv.conf")):
        run_cmd(["sudo", "rm", "-rf", ns_resolv_dir])

    # Load configuration for the namespace
    config_dir = f"/tmp/nnsctl/{ns_name}"
    if os.path.exists(config_dir):
        config_file = os.path.join(config_dir, "configuration.conf")
        namespace_config = load_namespace_config(ns_name)
        if namespace_config is not None:
            # Attempt to remove iptables rules (errors are ignored)
            ns_subnet = namespace_config["ns_subnet"]
            host_veth = namespace_config["host_veth"]
            scrub_routes(ns_subnet)
            scrub_iptables_rules(ns_subnet, host_veth)
            print(f"Routes and NAT rules scrubbed")
            # Deleting host_veth iface
            run_cmd("sudo ip link del " + host_veth, skip_error=True)
            print(f"Host interface {host_veth} deleted.")
        shutil.rmtree(config_dir, ignore_errors=True)
        print(f"Configuration directory {config_dir} removed.")

    # Check if any other managed namespaces exist
    if os.path.exists("/tmp/nnsctl"):
        remaining_namespaces = os.listdir("/tmp/nnsctl")
        if not remaining_namespaces:
            # Turn off IP forwarding if no other namespaces exist
            if is_ip_forwarding_enabled():
                disable_ip_forwarding()
                print("IP forwarding disabled as no other namespaces exist.")
            # Turn off route_localnet for the host lo interface just in case
            disable_route_localnet("lo")


def status_namespace(args):
    ns_name = args.ns_name
    existing = run_cmd(["ip", "netns", "list"], capture_output=True)

    if ns_name is None:
        print("Host Status:")
        print("IP Addresses")
        run_cmd("ip addr show")
        print("Routes")
        run_cmd("ip route show")
        print("IPTables")
        run_cmd("sudo iptables -S")
        print("IPTables NAT")
        run_cmd("sudo iptables -t nat -S")
        sys.exit(0)

    if ns_name not in existing:
        print(f"Namespace {ns_name} does not exist.")
        sys.exit(1)

    print(f"Namespace {ns_name}:")
    print("IP Addresses")
    run_cmd(f"sudo ip netns exec {ns_name} ip addr show")
    print("Routes")
    run_cmd(f"sudo ip netns exec {ns_name} ip route show")
    print("IPTables")
    run_cmd(f"sudo ip netns exec {ns_name} iptables -S")
    print("IPTables NAT")
    run_cmd(f"sudo ip netns exec {ns_name} iptables -t nat -S")

    config_file = f"/tmp/nnsctl/{ns_name}/configuration.conf"
    namespace_config = load_namespace_config(ns_name)
    if namespace_config is not None:
        pprint(namespace_config)


def exec_in_namespace(args):
    ns_name = args.ns_name
    if not args.command:
        print("No command specified for exec.")
        sys.exit(1)
    full_cmd = ["sudo", "ip", "netns", "exec", ns_name] + args.command
    subprocess.run(full_cmd)

def port_forward_add(args):
    ns_name = args.ns_name
    port = args.port
    namespace_config = load_namespace_config(ns_name)
    if namespace_config is None:
        print("Namespace not managed by nnsctl.")
        sys.exit(1)
    host_veth_ip_addr = namespace_config["host_veth_ip_addr"]
    host_veth = namespace_config["host_veth"]
    print(f"Forwarding port {port} for namespace {ns_name}")
    run_cmd(f"sudo ip netns exec {ns_name} iptables -t nat -A OUTPUT -p tcp --dport {port} -d 127.0.0.1 -j DNAT --to-destination {host_veth_ip_addr}:{port}")
    run_cmd(f"sudo iptables -t nat -A PREROUTING -p tcp -d {host_veth_ip_addr} --dport {port} -j DNAT --to-destination 127.0.0.1:{port}")
    print("Port forwarding rules added.")
    enable_route_localnet(host_veth)
    print(f"Enabled route_localnet for host interface {host_veth}.")


def port_forward_del(args):
    ns_name = args.ns_name
    port = args.port
    namespace_config = load_namespace_config(ns_name)
    if namespace_config is None:
        print("Namespace not managed by nnsctl.")
        sys.exit(1)
    host_veth_ip_addr = namespace_config["host_veth_ip_addr"]
    run_cmd(f"sudo ip netns exec {ns_name} iptables -t nat -D OUTPUT -p tcp --dport {port} -d 127.0.0.1 -j DNAT --to-destination {host_veth_ip_addr}:{port}", skip_error=True)
    run_cmd(f"sudo iptables -t nat -D PREROUTING -p tcp -d {host_veth_ip_addr} --dport {port} -j DNAT --to-destination 127.0.0.1:{port}", skip_error=True)
    print(f"Port forwarding rules for port {port} removed.")

x_ports_1 = "6000:6100"
x_ports_2 = "6000-6100"

def x_forward_add(args):
    ns_name = args.ns_name
    namespace_config = load_namespace_config(ns_name)
    if namespace_config is None:
        print("Namespace not managed by nnsctl.")
        sys.exit(1)
    host_veth_ip_addr = namespace_config["host_veth_ip_addr"]
    ns_veth_ip_addr = namespace_config["ns_veth_ip_addr"]
    host_veth = namespace_config["host_veth"]
    ns_veth = namespace_config["ns_veth"]
    print(f"Forwarding ports {x_ports_2} (Likely to be used by X server) for namespace {ns_name}")
    # Version 1
    #run_cmd(f"sudo ip netns exec {ns_name} iptables -t nat -A OUTPUT -p tcp --dport {x_ports_1} -d 127.0.0.1 -j DNAT --to-destination {host_veth_ip_addr}:{x_ports_2}")
    #run_cmd(f"sudo iptables -t nat -A PREROUTING -p tcp -d {host_veth_ip_addr} --dport {x_ports_1} -j DNAT --to-destination 127.0.0.1:{x_ports_2}")
    # Version 2
    ## Rules inside the namespace (explanation from Gemini)
    # Use the OUTPUT chain for locally generated packets
    # Use DNAT to change the destination IP from localhost to the host's veth IP
    run_cmd(f"sudo ip netns exec {ns_name} iptables -t nat -A OUTPUT -p tcp -d 127.0.0.1 --dport {x_ports_1} -j DNAT --to-destination {host_veth_ip_addr}")
    # Avoid martian source errors by changing the source IP to the namespace's veth IP
    run_cmd(f"sudo ip netns exec {ns_name} iptables -t nat -A POSTROUTING -o {ns_veth} -s 127.0.0.1 -d {host_veth_ip_addr} -p tcp --dport {x_ports_1} -j SNAT --to-source {ns_veth_ip_addr}")
    ## Rules inside the host namespace
    # Allow forwarding from the namespace veth to the loopback interface for X ports
    #run_cmd(f"sudo iptables -A FORWARD -i {host_veth} -o lo -p tcp  -d 127.0.0.2 --dport {x_ports_1} -j ACCEPT")
    run_cmd(f"sudo iptables -A FORWARD -i {host_veth} -o lo -p tcp  -d 127.0.0.1 --dport {x_ports_1} -j ACCEPT")
    # Allow related/established connections back (essential for TCP)
    # This rule is often present, but ensure it allows traffic back from loopback
    run_cmd(f"sudo iptables -A FORWARD -i lo -o {host_veth} -m state --state RELATED,ESTABLISHED -j ACCEPT")
    # PREROUTING (DNAT): Change destination IP from veth-host IP to localhost
    # Intercepts packets arriving on veth-host for itself on X ports
    #run_cmd(f"sudo iptables -t nat -A PREROUTING -i {host_veth} -p tcp --dport {x_ports_1} -j DNAT --to-destination 127.0.0.2")
    run_cmd(f"sudo iptables -t nat -A PREROUTING -i {host_veth} -p tcp --dport {x_ports_1} -j DNAT --to-destination 127.0.0.1")
    # POSTROUTING (SNAT): Change source IP to localhost (for xauth)
    # For packets going *to* the loopback interface for X ports, change their source IP
    # This helps satisfy xauth checks expecting connections from localhost
    #run_cmd(f"sudo iptables -t nat -A POSTROUTING -o lo -p tcp -d 127.0.0.2 --dport {x_ports_1} -s {ns_veth_ip_addr} -j SNAT --to-source 127.0.0.2")
    run_cmd(f"sudo iptables -t nat -A POSTROUTING -o lo -p tcp -d 127.0.0.1 --dport {x_ports_1} -s {ns_veth_ip_addr} -j SNAT --to-source 127.0.0.1")
    print("Port forwarding rules added.")
    enable_route_localnet(host_veth)
    enable_route_localnet("lo")
    enable_route_localnet(ns_veth, ns_name=ns_name)
    enable_route_localnet("lo", ns_name=ns_name)
    print(f"Enabled route_localnet for host interface {host_veth}.")


def x_forward_del(args):
    ns_name = args.ns_name
    namespace_config = load_namespace_config(ns_name)
    if namespace_config is None:
        print("Namespace not managed by nnsctl.")
        sys.exit(1)
    host_veth_ip_addr = namespace_config["host_veth_ip_addr"]
    run_cmd(f"sudo ip netns exec {ns_name} iptables -t nat -D OUTPUT -p tcp --dport {x_ports_1} -d 127.0.0.1 -j DNAT --to-destination {host_veth_ip_addr}:{x_ports_2}")
    run_cmd(f"sudo iptables -t nat -D PREROUTING -p tcp -d {host_veth_ip_addr} --dport {x_ports_1} -j DNAT --to-destination 127.0.0.1:{x_ports_2}")
    print(f"Port forwarding rules for ports {x_ports_2} removed.")


def list_namespaces(args):
    print("Listing network namespaces managed by nnsctl:")
    # We list namespaces that have a configuration file under /tmp/nnsctl.
    base_dir = "/tmp/nnsctl"
    if os.path.exists(base_dir):
        for ns in os.listdir(base_dir):
            print(ns)
    else:
        print("No namespaces found.")

def main():
    parser = argparse.ArgumentParser(prog="nnsctl", description="Network namespace control tool")
    parser.add_argument("--version", action="version", version=f"nnsctl {VERSION}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # list command
    parser_list = subparsers.add_parser("list", help="List network namespaces managed by nnsctl")
    parser_list.set_defaults(func=list_namespaces)

    def add_dry_run(parser):
        parser.add_argument("--dry-run", help="If passed report the commands that would be run but not execute them", action="store_true")

    # create command
    parser_create = subparsers.add_parser("create", help="Create a new network namespace")
    parser_create.add_argument("ns_name", help="Name of the network namespace")
    parser_create.add_argument("--host-if", help="Host interface to use")
    parser_create.add_argument("--ns-subnet", help="Namespace subnet to use")
    parser_create.add_argument("--host-ip", help="Host IP address")
    add_dry_run(parser_create)
    parser_create.set_defaults(func=create_namespace)

    # destroy command
    parser_destroy = subparsers.add_parser("destroy", help="Destroy a network namespace")
    parser_destroy.add_argument("ns_name", help="Name of the network namespace")
    parser_destroy.add_argument("--force", action="store_true", help="Force kill running processes in the namespace")
    add_dry_run(parser_destroy)
    parser_destroy.set_defaults(func=destroy_namespace)

    # status command
    parser_status = subparsers.add_parser("status", help="Get status of a network namespace")
    parser_status.add_argument("ns_name", nargs="?", help="Name of the network namespace")
    parser_status.set_defaults(func=status_namespace)

    # exec command
    parser_exec = subparsers.add_parser("exec", help="Execute a command inside a network namespace")
    parser_exec.add_argument("ns_name", help="Name of the network namespace")
    parser_exec.add_argument("command", nargs=argparse.REMAINDER, help="Command to execute")
    add_dry_run(parser_exec)
    parser_exec.set_defaults(func=exec_in_namespace)

    # port-forward command
    parser_port_forward = subparsers.add_parser("port-forward", help="Utilities for forwarding a port between host and namespace")
    port_forward_subparsers = parser_port_forward.add_subparsers(dest="subcommand", required=True)

    # port-forward add command
    parser_port_forward_add = port_forward_subparsers.add_parser("add", help="Add port forwarding for a particular port")
    parser_port_forward_add.add_argument("ns_name", help="Name of the network namespace")
    parser_port_forward_add.add_argument("port", type=int, help="Port number to forward")
    add_dry_run(parser_port_forward_add)
    parser_port_forward_add.set_defaults(func=port_forward_add)

    # port-forward del command
    parser_port_forward_del = port_forward_subparsers.add_parser("del", help="Delete port forwarding for a particular port")
    parser_port_forward_del.add_argument("ns_name", help="Name of the network namespace")
    parser_port_forward_del.add_argument("port", type=int, help="Port number to forward")
    add_dry_run(parser_port_forward_del)
    parser_port_forward_del.set_defaults(func=port_forward_del)

    # x-forward command
    parser_x_forward = subparsers.add_parser("x-forward", help="Forward X server ports (6000:6100) from host to namespace")
    parser_x_forward_subparsers = parser_x_forward.add_subparsers(dest="subcommand", required=True)

    # x-forward add command
    parser_x_forward_add = parser_x_forward_subparsers.add_parser("add", help="Add X server port forwarding")
    parser_x_forward_add.add_argument("ns_name", help="Name of the network namespace")
    add_dry_run(parser_x_forward_add)
    parser_x_forward_add.set_defaults(func=x_forward_add)

    # x-forward del command
    parser_x_forward_del = parser_x_forward_subparsers.add_parser("del", help="Delete X server port forwarding")
    parser_x_forward_del.add_argument("ns_name", help="Name of the network namespace")
    add_dry_run(parser_x_forward_del)
    parser_x_forward_del.set_defaults(func=x_forward_del)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
