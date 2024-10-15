#!/bin/bash

# Define the log file
LOG_FILE="user_audit.log"
ORIGINAL_LOG_FILE="/path/to/user_audit.log.original"

# Clear the log file if it exists
> "$LOG_FILE"

# Iterate over all users in /etc/passwd
while IFS=: read -r username _ uid gid _ home shell; do
    # Check *every* user, including system users
    if [ "$uid" -ge 0 ]; then
        # Get user permissions
        if [ -d "$home" ]; then
            permissions=$(ls -ld "$home" | awk '{print $1}')
        else
            permissions="N/A"
        fi

        # Get last login information
        lastlog_output=$(lastlog -u "$username" | tail -n 1)
        if echo "$lastlog_output" | grep -q "\*\*Never logged in\*\*"; then
            last_login="Never"
            login_ip="N/A"
        else
            # Extract last login date
            last_login=$(echo "$lastlog_output" | awk '{for (i=4;i<=NF;i++) printf("%s ", $i)}')
            # Get login IP
            login_ip=$(last -i "$username" | head -n 1 | awk '{print $3}')
        fi


        # Get user groups
        groups=$(id -Gn "$username" 2>/dev/null)
        if [ -z "$groups" ]; then
            groups="N/A"
        fi

        # Write user information to the log file
        echo "User: $username" >> "$LOG_FILE"
        echo "UID: $uid" >> "$LOG_FILE"
        echo "GID: $gid" >> "$LOG_FILE"
        echo "Home Directory: $home" >> "$LOG_FILE"
        echo "Shell: $shell" >> "$LOG_FILE"
        echo "Permissions: $permissions" >> "$LOG_FILE"
        echo "Last Login: $last_login" >> "$LOG_FILE"
        echo "Login IP: $login_ip" >> "$LOG_FILE"
        echo "Groups: $groups" >> "$LOG_FILE"
        echo "-------------------------" >> "$LOG_FILE"
    fi
done < /etc/passwd

echo "User audit log has been created at $LOG_FILE"

