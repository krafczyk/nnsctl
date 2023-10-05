#!/bin/bash

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
  echo "  -n, --ns-name       Namespace Name"
  echo "  --help              Display this help text and exit"
}

# Parse command line arguments
TEMP=$(getopt -o n:: --long ns-name::help -n "$0" -- "$@")

eval set -- "$TEMP"

while true; do
    case "$1" in
        -n|--ns-name) NS_NAME="$2"; shift 2;;
        --help) usage; exit 0;;
        --) shift; break;;
        *) echo "Invalid option"; usage; exit 1;;
    esac
done

# Default namespace
NS_NAME="nn_vpn"

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
