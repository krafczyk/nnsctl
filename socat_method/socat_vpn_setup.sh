#!/bin/bash

namespace="socat_vpn_ns"

# Create the network namespace
sudo ip netns add ${namespace}

# Start VPN in the network namespace
sudo ip netns exec ${namespace} openconnect --protocol=anyconnect vpn.illinois.edu &

# Sleep to allow VPN connection to establish
sleep 10

# Forward port 8080 through the VPN
sudo socat TCP4-LISTEN:8080,reuseaddr,fork,bind=127.0.0.1 EXEC:"ip netns $namespace socat STDIO TCP4:target:8008" &
