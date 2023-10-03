#!/bin/bash

NAMESPACE="myvpn"
PORT=""
veth0="veth0"
veth1="veth1"
VPN_PID=0
IP_FORWARD_ORIG=$(cat /proc/sys/net/ipv4/ip_forward)

setup_vpn() {
    # Create network namespace
    sudo ip netns add $NAMESPACE

    # Create veth pair and move veth1 to namespace
    sudo ip link add $veth0 type veth peer name $veth1
    sudo ip link set $veth1 netns $NAMESPACE

    # Configure IP addresses and bring up interfaces
    sudo ip addr add 192.168.1.1/24 dev $veth0
    sudo ip link set $veth0 up
    sudo ip netns exec $NAMESPACE ip addr add 192.168.1.2/24 dev $veth1
    sudo ip netns exec $NAMESPACE ip link set $veth1 up
    sudo ip netns exec $NAMESPACE ip route add default via 192.168.1.1

    # Enable IP forwarding and NAT
    sudo iptables -A FORWARD -o $veth0 -i tun0 -j ACCEPT
    sudo iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE

    # Set up port forwarding
    if [[ -n "$PORT" && "$PORT" -ge 1 && "$PORT" -le 65535 ]]; then
        sudo iptables -t nat -A PREROUTING -p tcp --dport $PORT -j DNAT --to-destination 192.168.1.2:$PORT
    fi

    if [ "$IP_FORWARD_ORIG" -eq 0 ]; then
        echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null
    fi

    # Run OpenConnect in the namespace
    sudo ip netns exec $NAMESPACE openconnect --protocol=anyconnect vpn.illinois.edu &
    VPN_PID=$!
}

teardown_vpn() {
    # If VPN_PID is not 0, kill it
    if [ $VPN_PID -ne 0 ]; then
        sudo kill -SIGINT $VPN_PID || true
    fi

    # Remove port forwarding
    if [[ -n "$PORT" && "$PORT" -ge 1 && "$PORT" -le 65535 ]]; then
        sudo iptables -t nat -D PREROUTING -p tcp --dport $PORT -j DNAT --to-destination 192.168.1.2:$PORT || true
    fi

    # Remove port forwarding and NAT
    sudo iptables -t nat -D POSTROUTING -o tun0 -j MASQUERADE || true
    sudo iptables -D FORWARD -o $veth0 -i tun0 -j ACCEPT || true

    # Disable IP forwarding
    if [ "$IP_FORWARD_ORIG" -eq 0 ]; then
        echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null
    fi

    # Delete network namespace and veth pair
    sudo ip netns del $NAMESPACE || true
    sudo ip link del $veth0 || true
}

# Trap keyboard interrupt (Ctrl+C)
trap teardown_vpn EXIT SIGINT SIGTERM

setup_vpn

# Wait for the VPN process to finish
if [ $VPN_PID -ne 0 ]; then
    wait $VPN_PID
fi
