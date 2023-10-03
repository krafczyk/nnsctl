#!/bin/bash

# Default namespace
NAMESPACE="myvpn"

# Check for namespace argument
if [ "$1" == "--namespace" ]; then
  shift
  NAMESPACE=$1
  shift
fi

# Get username
USERNAME=$(whoami)

# Run the command in the network namespace as the current user
sudo ip netns exec $NAMESPACE runuser -u $USERNAME -- "$@"
