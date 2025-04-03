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
        route_out = run_cmd(["ip", "route", "get", "8.8.8.8"], capture_output=True)
        # Example output: "8.8.8.8 via 192.168.1.1 dev eth0 src 192.168.1.100 ..."
        tokens = route_out.split()
        iface = tokens[tokens.index("dev") + 1]
        src_index = tokens.index("src") + 1
        ip_addr = tokens[src_index]
        return iface, ip_addr
    except Exception:
        print("No active non-loopback interface found.")
        sys.exit(1)


def load_namespace_config(config_file):
    if not os.path.exists(config_file):
        print(f"Configuration file {config_file} not found.")
        sys.exit(1)
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
    existing = run_cmd(["ip", "netns", "list"], capture_output=True)
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
    run_cmd(["sudo", "ip", "netns", "add", ns_name], dry_run=dry_run)
    print(f"Creating veth pair {host_veth} <-> {ns_veth}")
    run_cmd(["sudo", "ip", "link", "add", host_veth, "type", "veth", "peer", "name", ns_veth], dry_run=dry_run)
    print(f"Moving {ns_veth} into namespace {ns_name}")
    run_cmd(["sudo", "ip", "link", "set", ns_veth, "netns", ns_name], dry_run=dry_run)

    print("Configuring IP addresses and interfaces")
    # Assigning IP addresses
    run_cmd(["sudo", "ip", "addr", "add", f"{host_veth_ip_addr}/24", "dev", host_veth], dry_run=dry_run)
    run_cmd(["sudo", "ip", "netns", "exec", ns_name, "ip", "addr", "add", f"{ns_veth_ip_addr}/24", "dev", ns_veth], dry_run=dry_run)

    # Bring up the interfaces
    run_cmd(["sudo", "ip", "link", "set", host_veth, "up"], dry_run=dry_run)
    run_cmd(["sudo", "ip", "netns", "exec", ns_name, "ip", "link", "set", ns_veth, "up"], dry_run=dry_run)
    run_cmd(["sudo", "ip", "netns", "exec", ns_name, "ip", "link", "set", "lo", "up"], dry_run=dry_run)

    # Set default route within the namespace
    run_cmd(["sudo", "ip", "netns", "exec", ns_name, "ip", "route", "add", "default", "via", host_veth_ip_addr], dry_run=dry_run)

    print("Enabling IP forwarding")
    enable_ip_forwarding(dry_run=dry_run)

    # Use provided host_ip if given; otherwise, auto-detect
    if args.host_ip:
        host_ip = args.host_ip
    else:
        _, detected_ip = get_active_ip_iface()
        host_ip = detected_ip

    print("Setting iptables rules")
    #run_cmd(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-i", host_veth, "-d", host_ip, "-j", "DNAT", "--to-destination", "127.0.0.1"], dry_run=dry_run)
    #run_cmd(["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", host_veth, "-s", "127.0.0.1", "-j", "SNAT", "--to-source", host_ip], dry_run=dry_run)
    run_cmd(["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", f"{ns_subnet}/24", "-o", host_if, "-j", "MASQUERADE"], dry_run=dry_run)
    #run_cmd(["sudo", "iptables", "-A", "FORWARD", "-o", host_if, "-i", host_veth, "-j", "ACCEPT"], dry_run=dry_run)
    #run_cmd(["sudo", "iptables", "-A", "FORWARD", "-i", host_if, "-o", host_veth, "-j", "ACCEPT"], dry_run=dry_run)

    print("Configuring DNS for the namespace")
    ns_resolv_dir = f"/etc/netns/{ns_name}"
    run_cmd(["sudo", "mkdir", "-p", ns_resolv_dir], dry_run=dry_run)
    run_cmd(["sudo", "cp", "/etc/resolv.conf", os.path.join(ns_resolv_dir, "resolv.conf")], dry_run=dry_run)

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
        "forwarded_ports": []
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
    routes = run_cmd(["ip", "route", "show"], capture_output=True)
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


def scrub_iptables_rules(subnet):
    print("Checking iptables NAT rules...")
    subnet_triplet = '.'.join(subnet.split('.')[:3])
    print(f"scrub triplet: {subnet_triplet}")
    rules = run_cmd(["sudo", "iptables", "-t", "nat", "-S"], capture_output=True)
    if not rules:
        print("No iptables NAT rules found.")
        return
    for rule in rules.splitlines():
        # Check if the rule contains our problematic subnet
        if subnet_triplet in rule:
            # We only want to delte rules that were added (lines starting with "-A")
            if rule.startswith("-A"):
                delete_rule = rule.replace("-A", "-D", 1)
                cmd = ["sudo", "iptables", "-t", "nat"] + delete_rule.split()
                print(f"Deleting iptables rule: {delete_rule}")
                run_cmd(cmd)


def is_ip_forwarding_enabled() -> bool:
    if os.path.exists("/proc/sys/net/ipv4/ip_forward"):
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            return f.read().strip() == "1"
    return False


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
        if os.path.exists(config_file):
            namespace_config = load_namespace_config(config_file)

            # Attempt to remove iptables rules (errors are ignored)
            ns_subnet = namespace_config["ns_subnet"]
            scrub_routes(ns_subnet)
            scrub_iptables_rules(ns_subnet)
            print(f"Routes and NAT rules scrubbed")
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


def status_namespace(args):
    ns_name = args.ns_name
    existing = run_cmd(["ip", "netns", "list"], capture_output=True)
    if ns_name not in existing:
        print(f"Namespace {ns_name} does not exist.")
        sys.exit(1)

    print(f"Status for namespace {ns_name}:")
    print("Interfaces:")
    subprocess.run(["sudo", "ip", "netns", "exec", ns_name, "ip", "link", "show"])
    print("\nRouting table:")
    subprocess.run(["sudo", "ip", "netns", "exec", ns_name, "ip", "route", "show"])

    config_file = f"/tmp/nnsctl/{ns_name}/configuration.conf"
    if os.path.exists(config_file):
        print("\nConfiguration:")
        with open(config_file) as f:
            print(f.read())

def exec_in_namespace(args):
    ns_name = args.ns_name
    if not args.command:
        print("No command specified for exec.")
        sys.exit(1)
    full_cmd = ["sudo", "ip", "netns", "exec", ns_name] + args.command
    subprocess.run(full_cmd)

def forward_port(args):
    ns_name = args.ns_name
    port = args.port
    # For port forwarding we add DNAT and MASQUERADE rules.
    active_iface, _ = get_active_ip_iface()
    print(f"Forwarding port {port} for namespace {ns_name}")
    run_cmd(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-i", active_iface, "-p", "tcp",
             "--dport", str(port), "-j", "DNAT", "--to-destination", f"127.0.0.1:{port}"])
    run_cmd(["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", active_iface, "-p", "tcp",
             "--dport", str(port), "-j", "MASQUERADE"])
    print("Port forwarding rules added.")

def forward_x(args):
    # X forwarding uses port 6000 by default.
    args.port = 6000
    forward_port(args)

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
    parser_status.add_argument("ns_name", help="Name of the network namespace")
    parser_status.set_defaults(func=status_namespace)

    # exec command
    parser_exec = subparsers.add_parser("exec", help="Execute a command inside a network namespace")
    parser_exec.add_argument("ns_name", help="Name of the network namespace")
    parser_exec.add_argument("command", nargs=argparse.REMAINDER, help="Command to execute")
    add_dry_run(parser_exec)
    parser_exec.set_defaults(func=exec_in_namespace)

    # forward-port command
    parser_forward_port = subparsers.add_parser("forward-port", help="Forward a port from host to namespace")
    parser_forward_port.add_argument("ns_name", help="Name of the network namespace")
    parser_forward_port.add_argument("port", type=int, help="Port number to forward")
    add_dry_run(parser_forward_port)
    parser_forward_port.set_defaults(func=forward_port)

    # forward-x command
    parser_forward_x = subparsers.add_parser("forward-x", help="Forward X server port (6000) from host to namespace")
    parser_forward_x.add_argument("ns_name", help="Name of the network namespace")
    add_dry_run(parser_forward_x)
    parser_forward_x.set_defaults(func=forward_x)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
