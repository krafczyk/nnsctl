import os
from subprocess import CalledProcessError
from nsctl.processes import run_check_output, run_check, RunCheckOutputArgs
import re


def get_active_ip_iface() -> tuple[str, str]:
    """
    Get the active (non-loopback) interface and its IP.
    Uses 'ip route get 8.8.8.8' to determine the primary interface.
    """
    try:
        route_out = run_check_output("ip route get 8.8.8.8")
        # Example output: "8.8.8.8 via 192.168.1.1 dev eth0 src 192.168.1.100 ..."
        tokens = route_out.split()
        iface = tokens[tokens.index("dev") + 1]
        src_index = tokens.index("src") + 1
        ip_addr = tokens[src_index]
        return iface, ip_addr
    except CalledProcessError as e:
        raise RuntimeError(f"No active non-loopback interface found. {e}")


def scrub_routes_and_iptables(sentinel: str, cmd_opts: RunCheckOutputArgs|None=None):
    """
    Removes all routes and iptables entries that contain the given sentinel.
    """
    if cmd_opts is None:
        cmd_opts = {"escalate": "sudo"}

    # Remove routes
    routes = run_check_output("ip route show", **cmd_opts)
    for line in routes.splitlines():
        # Check if the rule contains our sentinel
        if sentinel in line:
            print(f"Removing route: {line}")
            # Remove the route by reusing the route specification.
            # This may fail if additional fields cause mismatches, so you might need to adjust the parsing.
            run_check(["ip", "route", "del"] + line.split(), **cmd_opts)

    # Remove iptables rules
    rules = run_check_output(["iptables", "-S"], **cmd_opts)
    for rule in rules.splitlines():
        # Check if the rule contains our sentinel
        if sentinel in rule:
            # We only want to delete rules that were added (lines starting with "-A")
            if rule.startswith("-A"):
                delete_rule = rule.replace("-A", "-D", 1)
                cmd = ["iptables" ] + delete_rule.split()
                run_check(cmd, **cmd_opts)

    # Remove iptables NAT rules
    rules = run_check_output(["iptables", "-t", "nat", "-S"], **cmd_opts)
    for rule in rules.splitlines():
        # Check if the rule contains our sentinel
        if sentinel in rule:
            # We only want to delte rules that were added (lines starting with "-A")
            if rule.startswith("-A"):
                delete_rule = rule.replace("-A", "-D", 1)
                cmd = ["iptables", "-t", "nat"] + delete_rule.split()
                run_check(cmd, **cmd_opts)





def scrub_routes(subnet: str):
    print("Checking host routes...")
    routes = run_check_output("ip route show")
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
            run_check(["ip", "route", "del"] + line.split(), escalate="sudo")


def scrub_iptables_rules(subnet: str, iface: str):
    print("Checking iptables NAT rules...")
    subnet_triplet = '.'.join(subnet.split('.')[:3])
    print(f"scrub triplet: {subnet_triplet}")
    rules = run_check_output(["iptables", "-t", "nat", "-S"], escalate="sudo")
    if rules:
        for rule in rules.splitlines():
            # Check if the rule contains our problematic subnet
            if subnet_triplet in rule:
                # We only want to delte rules that were added (lines starting with "-A")
                if rule.startswith("-A"):
                    delete_rule = rule.replace("-A", "-D", 1)
                    cmd = ["iptables", "-t", "nat"] + delete_rule.split()
                    print(f"Deleting iptables NAT rule: {delete_rule}")
                    run_check(cmd, escalate="sudo")

    print("Checking iptables routing rules...")
    rules = run_check_output(["iptables", "-S"], escalate="sudo")
    if rules:
        for rule in rules.splitlines():
            # Check if the rule contains our problematic subnet
            if iface in rule:
                # We only want to delte rules that were added (lines starting with "-A")
                if rule.startswith("-A"):
                    delete_rule = rule.replace("-A", "-D", 1)
                    cmd = ["iptables" ] + delete_rule.split()
                    print(f"Deleting iptables routing rule: {delete_rule}")
                    run_check(cmd, escalate="sudo")


def is_ip_forwarding_enabled() -> bool:
    if os.path.exists("/proc/sys/net/ipv4/ip_forward"):
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            return f.read().strip() == "1"
    return False


def enable_route_localnet(iface: str, ns_name: str|None=None, dry_run:bool=False):
    if ns_name is None:
        run_check(
            f"sysctl -w net.ipv4.conf.{iface}.route_localnet=1",
            dry_run=dry_run,
            escalate="sudo")
    else:
        run_check(
            f"ip netns exec {ns_name} sysctl -w net.ipv4.conf.{iface}.route_localnet=1",
            dry_run=dry_run,
            escalate="sudo")


def disable_route_localnet(iface: str , ns_name: str|None=None, dry_run:bool=False):
    if ns_name is None:
        run_check(
            f"sysctl -w net.ipv4.conf.{iface}.route_localnet=0",
            dry_run=dry_run,
            escalate="sudo")
    else:
        run_check(
            f"ip netns exec {ns_name} sysctl -w net.ipv4.conf.{iface}.route_localnet=0",
            dry_run=dry_run,
            escalate="sudo")


def enable_ip_forwarding(dry_run:bool=False):
    run_check(
        "sysctl -w net.ipv4.ip_forward=1",
        dry_run=dry_run,
        escalate="sudo")


def disable_ip_forwarding(dry_run:bool=False):
    run_check(
        "sysctl -w net.ipv4.ip_forward=0",
        dry_run=dry_run,
        escalate="sudo")


def extract_ipv4_address(ip_addr_output: str, interface_name: str) -> str | None:
    """
    Extracts the primary global IPv4 address for a specific interface
    from the output of 'ip addr show <interface>'.

    Args:
        ip_addr_output: The multi-line string output from 'ip addr show'.
        interface_name: The name of the interface (e.g., 'macvlan0').

    Returns:
        The extracted IPv4 address (without CIDR) as a string,
        or None if no matching address is found.
    """
    # Regex explanation:
    # \s*inet\s+             # Match 'inet' surrounded by optional whitespace
    # (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) # Capture the IPv4 address (group 1)
    # /\d{1,2}              # Match the CIDR prefix (e.g., /24)
    # .* # Match any characters (like brd, scope)
    # scope\s+global        # Ensure it's a global scope address
    # \s+                     # Match whitespace
    # {re.escape(interface_name)} # Match the specific interface name
    # $                     # Ensure it's at the end of the line (or followed by newline)
    pattern = re.compile(
        rf"^\s*inet\s+(\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}})/\d{{1,2}}.*scope\s+global\s+{re.escape(interface_name)}$",
        re.MULTILINE
    )

    match = pattern.search(ip_addr_output)
    if match:
        return match.group(1) # Return the captured IP address part
    return None
