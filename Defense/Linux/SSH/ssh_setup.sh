#!/bin/bash

<<~~###############################################################################

NOT CURRENTLY WORKING - Checking for pre-existing keys fails.


This script scans the system for pre-existing SSH keys and then stands up SSH on a server, creates a user, and adds SSH keys to the user's authorized_keys file. It then prompts for a password for the user.

~~###############################################################################

# Ensure the script is being run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root or with sudo"
  exit 1
fi

# Step 1: Check for pre-existing SSH keys in the system
echo "Searching for pre-existing SSH keys in the system..."

# Log file to store findings
KEY_LOG="/tmp/ssh_key_check.log"
> $KEY_LOG

# Find SSH public keys (.pub or files containing ssh-rsa/ecdsa/ed25519 keys)
# find / -type f -exec grep -EH "ssh-(rsa|dss|ecdsa|ed25519)" {} \; >> $KEY_LOG 2>/dev/null
# Does not work as intended yet. Need to refine the search.

echo "Finished scanning. SSH key search results stored in $KEY_LOG."

# Step 2: Install OpenSSH if not already installed
echo "Checking if OpenSSH is installed..."

# Function to install OpenSSH based on the package manager
install_openssh() {
  if command -v apt >/dev/null 2>&1; then
    apt update && apt install -y openssh-server
  elif command -v yum >/dev/null 2>&1; then
    yum install -y openssh-server
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y openssh-server
  elif command -v zypper >/dev/null 2>&1; then
    zypper install -y openssh
  else
    echo "Unsupported package manager. Please install OpenSSH manually."
    exit 1
  fi
}

# Check if OpenSSH is installed
if ! systemctl is-active --quiet sshd; then
  echo "OpenSSH is not installed. Installing..."
  install_openssh
  echo "OpenSSH installed."
fi

# Enable and start the OpenSSH service
systemctl enable sshd
systemctl start sshd

# Step 3: Ensure 'blueteam' user exists, create if not
echo "Ensuring user 'blueteam' exists..."
if ! id -u blueteam >/dev/null 2>&1; then
  echo "Creating user 'blueteam'..."
  useradd -m -s /bin/bash blueteam
  echo "User 'blueteam' created."
else
  echo "User 'blueteam' already exists."
fi

# Step 4: Append SSH keys from provided file to 'authorized_keys'
read -p "Please provide the path to the file containing SSH keys: " SSH_KEY_FILE

if [[ -f "$SSH_KEY_FILE" ]]; then
  echo "Adding keys to /home/blueteam/.ssh/authorized_keys..."
  
  # Ensure .ssh directory exists and correct permissions are set
  SSH_DIR="/home/blueteam/.ssh"
  AUTH_KEYS_FILE="$SSH_DIR/authorized_keys"

  mkdir -p "$SSH_DIR"
  touch "$AUTH_KEYS_FILE"
  cat "$SSH_KEY_FILE" >> "$AUTH_KEYS_FILE"

  # Set appropriate permissions
  chown -R blueteam:blueteam "$SSH_DIR"
  chmod 700 "$SSH_DIR"
  chmod 600 "$AUTH_KEYS_FILE"

  echo "Keys added to authorized_keys."
else
  echo "File '$SSH_KEY_FILE' does not exist."
  exit 1
fi

# Step 5: Prompt for a password and securely update 'blueteam' user's password
echo "Please enter a password for the 'blueteam' user."
echo "Note: You will not see the password as you type."

# Using passwd to securely set or update the user's password
passwd blueteam

# Final confirmation
echo "SSH setup complete for user 'blueteam'."
