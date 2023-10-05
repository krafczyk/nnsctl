#!/bin/bash

NS_NAME="myvpn"
NS_EXEC="sudo -E ip netns exec $NS_NAME"
VPN_USER="mkrafcz2"
WIRED_IF="enp5s0" # We may need to add additional interfaces.
OUT_IF="${NS_NAME}0"
IN_IF="${NS_NAME}1"
#OUT_IP=192.168.1.1
#IN_IP=192.168.1.2
OUT_IP=192.168.3.1
IN_IP=192.168.3.2
vpn_pid_file="vpn.pid"
vpn_interface="vpn0"
VPN_ENDPOINT="vpn.illinois.edu"

# Save current state of IP forwarding
IP_FORWARD_ORIG=$(cat /proc/sys/net/ipv4/ip_forward)

# Save current state of lo local routing
LO_LOCAL_ROUTING=$(cat /proc/sys/net/ipv4/conf/lo/route_localnet)

# Validation on whether the namespace exists
if sudo ip netns list | grep -q $NS_NAME; then
    echo "Namespace $NS_NAME already exists"
    exit 1
fi

# Check whether the pid file is available
if [ -e "$vpn_pid_file" ]; then
    echo "VPN process already running"
    exit 1
fi

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
    sudo iptables -t nat -A PREROUTING -i $OUT_IF -d 192.168.2.31 -j DNAT --to-destination 127.0.0.1
    sudo iptables -t nat -A POSTROUTING -o $OUT_IF -s 127.0.0.1 -j SNAT --to-source 192.168.2.31
    # Direct traffic out of the namespace to the internet
    sudo iptables -t nat -A POSTROUTING -s $OUT_IP/24 -o $WIRED_IF -j MASQUERADE
    # Traffic from the internet to the namespace
    sudo iptables -A FORWARD -o $WIRED_IF -i $OUT_IF -j ACCEPT
    sudo iptables -A FORWARD -i $WIRED_IF -o $OUT_IF -j ACCEPT

    # Run OpenConnect in the namespace
    echo "Starting VPN..."
    $NS_EXEC openconnect -b --interface $vpn_interface --user=${VPN_USER} --authgroup=3_TunnelAll --protocol=anyconnect $VPN_ENDPOINT

    # Wait for $vpn_inteface interface to be created
    while ! $NS_EXEC ip link show dev $vpn_interface >/dev/null 2>&1; do sleep .5; done;

    # Ensure lo local routing is enabled
    echo "Enabling lo local routing"
    echo 1 | sudo tee /proc/sys/net/ipv4/conf/lo/route_localnet > /dev/null

    # Set local routing for $OUT_IF
    echo 1 | sudo tee /proc/sys/net/ipv4/conf/$OUT_IF/route_localnet > /dev/null
}

delete_rule() {
    sudo iptables -C $@ 2>/dev/null
    if [ $? -eq 0 ]; then
        sudo iptables -D $@
    fi
}

teardown_vpn() {
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
    delete_rule -t nat -D PREROUTING -i $OUT_IF -d 192.168.2.31 -j DNAT --to-destination 127.0.0.1 || true
    delete_rule -t nat -D POSTROUTING -o $OUT_IF -s 127.0.0.1 -j SNAT --to-source 192.168.2.31 || true
    delete_rule -D FORWARD -i $WIRED_IF -o $OUT_IF -j ACCEPT || true
    delete_rule -D FORWARD -o $WIRED_IF -i $OUT_IF -j ACCEPT || true
    delete_rule -t nat -D POSTROUTING -s $OUT_IP/24 -o $WIRED_IF -j MASQUERADE || true

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
while sudo ip netns pids $NS_NAME | grep -q .; do sleep .5; done;
