import sys
from nsctl.proesses import run_cmd


def get_active_ip_iface() -> tuple[str, str]:
    """
    Get the active (non-loopback) interface and its IP.
    Uses 'ip route get 8.8.8.8' to determine the primary interface.
    """
    try:
        result = run_cmd("ip route get 8.8.8.8", capture_output=True)
        if result is None:
            raise RuntimeError("No result from command")
        route_out = result.stdout
        # Example output: "8.8.8.8 via 192.168.1.1 dev eth0 src 192.168.1.100 ..."
        tokens = route_out.split()
        iface = tokens[tokens.index("dev") + 1]
        src_index = tokens.index("src") + 1
        ip_addr = tokens[src_index]
        return iface, ip_addr
    except Exception:
        print("No active non-loopback interface found.")
        sys.exit(1)


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

