#!/bin/bash

set -e

# Find and load default values from config file
CONFIG_FILE="$(dirname "$0")/vpn_config.sh"
if [ -f "$CONFIG_FILE" ]; then
  source "$CONFIG_FILE"
else
  echo "Config file vpn_config.sh not found. Using built-in defaults."
fi

# Usage function for help text
usage() {
  echo "Usage: $0 [options]"
  echo "Options:"
  echo "  -u, --user          VPN User"
  echo "  -a, --authgroup     VPN Authgroup"
  echo "  -n, --ns-name       Namespace Name"
  echo "  -v, --vpn-if        VPN Interface"
  echo "  -e, --vpn-endpoint  VPN Endpoint"
  echo "  -h, --host-if       Host Interface"
  echo "  -i, --host-ip       Host IP"
  echo "  -s, --subnet        Subnet to use"
  echo "  --help              Display this help text and exit"
}

# Parse command line arguments
TEMP=$(getopt -o u::a::n::v::e::h::i::s:: --long user::,authgroup::,ns-name::,vpn-if::,vpn-endpoint::,host-if::,host-ip::,subnet::,help -n "$0" -- "$@")

eval set -- "$TEMP"

while true; do
    case "$1" in
        -u|--user) USER="$2"; shift 2;;
        -a|--authgroup) AUTHGROUP="$2"; shift 2;;
        -n|--ns-name) NS_NAME="$2"; shift 2;;
        -v|--vpn-if) VPN_IF="$2"; shift 2;;
        -e|--vpn-endpoint) VPN_ENDPOINT="$2"; shift 2;;
        -h|--host-if) HOST_IF="$2"; shift 2;;
        -i|--host-ip) HOST_IP="$2"; shift 2;;
        -s|--subnet) SUBNET="$2"; shift 2;;
        --help) usage; exit 0;;
        --) shift; break;;
        *) echo "Invalid option"; usage; exit 1;;
    esac
done

get_active_ip_iface() {
    ip_data=$(ip -4 addr show scope global | grep -Eo 'inet [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}')
    for ip in $ip_data; do
        iface=$(ip -4 addr | grep $ip | awk '{print $NF}')
        status=$(cat /sys/class/net/$iface/operstate)
        if [ "$status" == "up" ]; then
            echo "$iface $ip"
            return 0
        fi
    done
    echo "No active non-loopback interfaces found."
    exit 1
}

read -r HOST_IF HOST_IP <<< "$(get_active_ip_iface)"
echo "Using interface: $HOST_IF, IP: $HOST_IP"

OUT_IP="${SUBNET}.1"
OUT_IF="${NS_NAME}0"
IN_IP="${SUBNET}.2"
IN_IF="${NS_NAME}1"

NS_EXEC="sudo -E ip netns exec $NS_NAME"

# Save current state of IP forwarding
IP_FORWARD_ORIG=$(cat /proc/sys/net/ipv4/ip_forward)

# Save current state of lo local routing
LO_LOCAL_ROUTING=$(cat /proc/sys/net/ipv4/conf/lo/route_localnet)

# Validation on whether the namespace exists
if sudo ip netns list | grep -q $NS_NAME; then
    echo "Namespace $NS_NAME already exists"
    exit 1
fi

terminate=0

setup_vpn() {
    # Create network namespace
    echo "Creating network namespace ${NS_NAME}"
    sudo ip netns add $NS_NAME

    # Create network interface pair and move $IN_IF to namespace
    echo "Creating network interface pair"
    sudo ip link add $OUT_IF type veth peer name $IN_IF
    sudo ip link set $IN_IF netns $NS_NAME

    # Configure IP addresses and bring up interfaces
    echo "Configuring IP addresses and routing"
    # Configure IP addresses for veth pair
    sudo ip addr add $OUT_IP/24 dev $OUT_IF
    $NS_EXEC ip addr add $IN_IP/24 dev $IN_IF
    # Bring up new interfaces
    sudo ip link set $OUT_IF up
    $NS_EXEC ip link set $IN_IF up
    $NS_EXEC ip link set lo up
    # Create routes for namespace
    $NS_EXEC ip route add default via $OUT_IP dev $IN_IF
    $NS_EXEC ip route add 192.168.2.0/24 via $OUT_IP dev $IN_IF

    # Ensure IP forwarding is enabled
    echo "Enabling IP Forwarding"
    echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null

    # Configure the nameserver to use inside the namespace
    # TODO use VPN-provided DNS servers in order to prevent leaks
    echo "Configuring DNS nameserver"
    sudo mkdir -p /etc/netns/${NS_NAME}
    sudo cp /etc/resolv.conf /etc/netns/${NS_NAME}

    # Fix direct traffic destined for host ip to host lo
    echo "Setting iptables rules"
    sudo iptables -t nat -A PREROUTING -i $OUT_IF -d $HOST_IP -j DNAT --to-destination 127.0.0.1
    sudo iptables -t nat -A POSTROUTING -o $OUT_IF -s 127.0.0.1 -j SNAT --to-source $HOST_IP
    # Direct traffic out of the namespace to the internet
    sudo iptables -t nat -A POSTROUTING -s $OUT_IP/24 -o $HOST_IF -j MASQUERADE
    # Traffic from the internet to the namespace
    sudo iptables -A FORWARD -o $HOST_IF -i $OUT_IF -j ACCEPT
    sudo iptables -A FORWARD -i $HOST_IF -o $OUT_IF -j ACCEPT

    # Run OpenConnect in the namespace
    echo "Starting VPN..."
    $NS_EXEC openconnect -b --interface $VPN_IF --user=${USER} --authgroup=$AUTHGROUP --protocol=anyconnect $VPN_ENDPOINT

    # Wait for $vpn_inteface interface to be created
    while [ "$terminate" -ne 1 ] && ! $NS_EXEC ip link show dev $VPN_IF >/dev/null 2>&1; do
        sleep .5;
    done;

    # Ensure lo local routing is enabled
    echo "Enabling lo local routing"
    echo 1 | sudo tee /proc/sys/net/ipv4/conf/lo/route_localnet > /dev/null

    # Set local routing for $OUT_IF
    echo 1 | sudo tee /proc/sys/net/ipv4/conf/$OUT_IF/route_localnet &> /dev/null
}

delete_rule() {
    sudo iptables -C $@ 2>/dev/null
    if [ $? -eq 0 ]; then
        sudo iptables -D $@
    fi
}

teardown_vpn() {
    set +e
    terminate=1

    echo "Stopping VPN and other processes within the network namespace $NS_NAME"
    pids=$(sudo ip netns pids $NS_NAME)
    # First try to terminate
    for pid in $pids; do
        sudo kill -TERM $pid
    done

    # Wait for processes to terminate
    sleep 5

    for pid in $pids; do
        if sudo kill -0 $pid 2>/dev/null; then
            sudo kill -KILL $pid
        fi
    done 

    # Remove iptables rules
    echo "Removing iptables rules"
    delete_rule -t nat -D PREROUTING -i $OUT_IF -d $HOST_IP -j DNAT --to-destination 127.0.0.1 || true
    delete_rule -t nat -D POSTROUTING -o $OUT_IF -s 127.0.0.1 -j SNAT --to-source $HOST_IP || true
    delete_rule -D FORWARD -i $HOST_IF -o $OUT_IF -j ACCEPT || true
    delete_rule -D FORWARD -o $HOST_IF -i $OUT_IF -j ACCEPT || true
    delete_rule -t nat -D POSTROUTING -s $OUT_IP/24 -o $HOST_IF -j MASQUERADE || true

    # Disable IP forwarding
    if [ "$IP_FORWARD_ORIG" -eq 0 ]; then
        echo "Disabling IP Forwarding"
        echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null
    fi

    # Disable lo local routing if necessary
    if [ "$LO_LOCAL_ROUTING" -eq 0 ]; then
        echo "Disabling lo local routing"
        echo 0 | sudo tee /proc/sys/net/ipv4/conf/lo/route_localnet > /dev/null
    fi

    # Delete nameserver configuration
    echo "Deleting nameserver configuration"
    if [ -e "/etc/netns/${NS_NAME}/resolv.conf" ]; then
        sudo rm -r /etc/netns/${NS_NAME}/resolv.conf
    fi

    # Delete network namespace and veth pair
    if sudo ip netns list | grep -q "$NS_NAME"; then
        echo "Deleting network namespace $NS_NAME"
        sudo ip netns del $NS_NAME || true
    fi
}

# Trap keyboard interrupt (Ctrl+C)
trap teardown_vpn EXIT SIGINT SIGTERM

setup_vpn

# Wait for processes in the network namespace to finish
while [ "$terminate" -ne 1 ]; do
    PIDS=$(sudo ip netns pids $NS_NAME 2> /dev/null)
    if [[ $? -ne 0 || -z "$PIDS" ]]; then
        break
    fi
    sleep .5
done
