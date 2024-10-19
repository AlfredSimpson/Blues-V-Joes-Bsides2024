#!/bin/bash

# DNS Setup Script - Compatible with multiple Linux distros (I hope)

# Variables (update these as needed)
DOMAIN="pvj.example"
REVERSE_ZONE="10.10.10.in-addr.arpa"
IP="10.10.10.100"
NS1="ns1.$DOMAIN"
NS2="ns2.$DOMAIN"
LAST_OCTET=$(echo $IP | awk -F '.' '{print $4}')  # Extract the last octet from IP address

# Detect Linux distribution and package manager
if [ -f /etc/debian_version ]; then
    PKG_MANAGER="apt"
    UPDATE_CMD="apt update"
    INSTALL_CMD="apt install -y bind9 bind9utils bind9-doc"
elif [ -f /etc/redhat-release ]; then
    PKG_MANAGER="yum"
    UPDATE_CMD="yum makecache fast"
    INSTALL_CMD="yum install -y bind bind-utils"
elif [ -f /etc/fedora-release ]; then
    PKG_MANAGER="dnf"
    UPDATE_CMD="dnf makecache"
    INSTALL_CMD="dnf install -y bind bind-utils"
else
    echo "Unsupported Linux distribution."
    exit 1
fi

echo "Detected package manager: $PKG_MANAGER"

# Wipe existing bind configuration (optional: for fresh setup)
echo "Wiping existing DNS configuration..."
rm -rf /etc/bind/zones/db.*
rm -rf /etc/bind/named.conf.local

# Update package list and install DNS server (bind)
echo "Updating package list..."
$UPDATE_CMD

echo "Installing DNS server..."
$INSTALL_CMD

# Configure named.conf.local
NAMED_CONF_LOCAL="/etc/bind/named.conf.local"
if [ ! -f "$NAMED_CONF_LOCAL" ]; then
    touch $NAMED_CONF_LOCAL  # Ensure the file exists
fi

cat <<EOF > $NAMED_CONF_LOCAL
zone "$DOMAIN" {
    type master;
    file "/etc/bind/zones/db.$DOMAIN";
};

zone "$REVERSE_ZONE" {
    type master;
    file "/etc/bind/zones/db.$REVERSE_ZONE";
};
EOF

# Create directories for zone files
mkdir -p /etc/bind/zones

# Create Forward Zone file with corrected NS and A records
cat <<EOF > /etc/bind/zones/db.$DOMAIN
\$TTL 604800
@   IN  SOA $NS1. admin.$DOMAIN. (
            2      ; Serial
        604800     ; Refresh
         86400     ; Retry
       2419200     ; Expire
        604800 )   ; Negative Cache TTL
;
@   IN  NS  $NS1.
@   IN  NS  $NS2.
$NS1    IN  A   $IP
$NS2    IN  A   $IP
EOF

# Create Reverse Zone file with dynamic last octet for PTR record
cat <<EOF > /etc/bind/zones/db.$REVERSE_ZONE
\$TTL 604800
@   IN  SOA $NS1. admin.$DOMAIN. (
            2         ; Serial
        604800     ; Refresh
         86400     ; Retry
       2419200     ; Expire
        604800 )   ; Negative Cache TTL
;
@   IN  NS  $NS1.
$LAST_OCTET IN  PTR $DOMAIN.
EOF

# Adjust AppArmor for Debian-based systems (including Kali)
if [ "$PKG_MANAGER" = "apt" ]; then
    echo "Configuring AppArmor..."
    APPARMOR_CONF="/etc/apparmor.d/local/usr.sbin.named"
    echo "/etc/bind/zones/* rw," >> $APPARMOR_CONF
    systemctl restart apparmor
fi

# Restart bind service (handles both bind9 and named)
echo "Restarting DNS server..."

if systemctl status bind9 &> /dev/null; then
    systemctl restart bind9
elif systemctl status named &> /dev/null; then
    systemctl restart named
else
    echo "Neither bind9 nor named service found. Attempting to start bind9 manually..."
    systemctl start bind9
fi

# Optional: Validate the zone files
echo "Validating forward zone..."
named-checkzone $DOMAIN /etc/bind/zones/db.$DOMAIN

echo "Validating reverse zone..."
named-checkzone $REVERSE_ZONE /etc/bind/zones/db.$REVERSE_ZONE

echo "DNS setup completed."
