#!/bin/bash

# Namespace name as a variable
namespace="socat_vpn_ns"

# Kill socat and openconnect processes
sudo pkill -f 'socat TCP4-LISTEN:8080'
sudo pkill -f 'openconnect --protocol=anyconnect'

# Delete the network namespace
sudo ip netns del $namespace
