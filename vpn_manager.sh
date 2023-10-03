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
    sudo ip link set $OUT_IF up
    sudo ip link set $IN_IF netns $NS_NAME

    # Configure IP addresses and bring up interfaces
    echo "Configuring IP addresses and routing"
    sudo ip addr add $OUT_IP/24 dev $OUT_IF
    $NS_EXEC ip addr add $IN_IP/24 dev $IN_IF
    $NS_EXEC ip link set $IN_IF up
    $NS_EXEC ip route add default via $OUT_IP dev $IN_IF
    $NS_EXEC ip link set lo up

    # Ensure IP forwarding is enabled
    if [ "$IP_FORWARD_ORIG" -eq 0 ]; then
        echo "Enabling IP Forwarding"
        echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null
    fi

    # Configure the nameserver to use inside the namespace
    # TODO use VPN-provided DNS servers in order to prevent leaks
    echo "Configuring DNS nameserver"
    sudo mkdir -p /etc/netns/${NS_NAME}
    sudo cp /etc/resolv.conf /etc/netns/${NS_NAME}

    sudo iptables -t nat -A POSTROUTING -s $OUT_IP/24 -o $WIRED_IF -j MASQUERADE
    sudo iptables -A FORWARD -o $WIRED_IF -i $OUT_IF -j ACCEPT
    sudo iptables -A FORWARD -i $WIRED_IF -o $OUT_IF -j ACCEPT

    $NS_EXEC ping -c 5 127.0.0.1
    $NS_EXEC ping -c 5 localhost
    $NS_EXEC ping -c 5 8.8.8.8
    $NS_EXEC ping -c 5 192.168.2.1
    $NS_EXEC ping -c 5 google.com
    $NS_EXEC ping -c 5 ${VPN_ENDPOINT}

    ## Run OpenConnect in the namespace
    #echo "Starting VPN..."
    #$NS_EXEC openconnect -b --interface $vpn_interface --pid-file=$vpn_pid_file --user=${VPN_USER} --pro#tocol=anyconnect $VPN_ENDPOINT
    ##$NS_EXEC openconnect -b --interface $vpn_interface --user=${VPN_USER} --protocol=anyconnect $VPN_ENDPOINT

    ## Wait for $vpn_inteface interface to be created
    #while ! $NS_EXEC ip link show dev $vpn_interface >/dev/null 2>&1; do sleep .5; done;

    ## Enable IP forwarding and NAT
    #echo "Creating iptables rules"
    #sudo iptables -A FORWARD -o $OUT_IF -i $vpn_interface -j ACCEPT
    #sudo iptables -t nat -A POSTROUTING -o $vpn_interface -j MASQUERADE
}

teardown_vpn() {
    ## If VPN_PID is not 0, kill it
    ##VPN_PID=$(cat $vpn_pid_file)
    ##sudo kill -SIGINT $VPN_PID || true
    #echo "Stopping VPN and other processes within the network namespace $NS_NAME"
    #sudo ip netns pids $NS_NAME | sudo xargs -rd'\n' kill -SIGINT
#
#    sleep 2

    ## Remove port forwarding and NAT
    #echo "Removing iptables rules"
    #sudo iptables -t nat -D POSTROUTING -o $vpn_interface -j MASQUERADE || true
    #sudo iptables -D FORWARD -o $OUT_IF -i $vpn_interface -j ACCEPT || true

    sudo iptables -D FORWARD -i $WIRED_IF -o $OUT_IF -j ACCEPT || true
    sudo iptables -D FORWARD -o $WIRED_IF -i $OUT_IF -j ACCEPT || true
    sudo iptables -t nat -D POSTROUTING -o $WIRED_IF -j MASQUERADE || true

    # Disable IP forwarding
    if [ "$IP_FORWARD_ORIG" -eq 0 ]; then
        echo "Disabling IP Forwarding"
        echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null
    fi

    # Delete nameserver configuration
    sudo rm -r /etc/netns/${NS_NAME}

    # Delete network namespace and veth pair
    echo "Deleting network namespace $NS_NAME"
    sudo ip netns del $NS_NAME || true
    echo "Deleting remaining network interface $OUT_IF"
    sudo ip link del $OUT_IF || true
}

# Trap keyboard interrupt (Ctrl+C)
trap teardown_vpn EXIT SIGINT SIGTERM

setup_vpn

## Wait for the VPN process to finish
#VPN_PID=$(cat $vpn_pid_file)
#if [ $VPN_PID -ne 0 ]; then
#    wait $VPN_PID
#fi
