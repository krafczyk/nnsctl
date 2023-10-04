#!/bin/bash

# Default namespace
NS_NAME="myvpn"

# Check for namespace argument
if [ "$1" == "--namespace" ]; then
  shift
  NS_NAME=$1
  shift
fi

# Get username
USERNAME=$(whoami)

# Run the command in the network namespace as the current user
sudo -E ip netns exec $NS_NAME runuser -u $USERNAME -- "$@"
