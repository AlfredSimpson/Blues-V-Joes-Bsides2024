#!/bin/bash

# Define the paths after they have been set.
AUDIT_SCRIPT="/path/to/audit.sh"
LOG_FILE="/path/to/user_audit.log"
PREV_LOG_FILE="/path/to/user_audit.log.prev"
ORIGINAL_LOG_FILE="/path/to/user_audit.log.original"

# Run the audit script
"$AUDIT_SCRIPT"

# Compare the new log with the previous one
if [ -e "$PREV_LOG_FILE" ]; then
    if ! cmp -s "$LOG_FILE" "$PREV_LOG_FILE"; then
        # Anomalies detected, send message to XXXXXXXXXXXXXXXXX
        {
            echo "Anomaly detected in user audit log:"
            diff -C 5 "$PREV_LOG_FILE" "$LOG_FILE"
        } | mail -s "User Audit Alert" XXXXXXXXXXXXXXXXX
        echo "Anomaly detected. Check mail."
    fi
else
    # First run, set up the baseline log file
    echo "First run: creating baseline user audit log."
    # Hide and perm lock the original log file
    cp "$LOG_FILE" "$ORIGINAL_LOG_FILE"
    chmod 400 "$ORIGINAL_LOG_FILE"
fi

# Update the previous log file for the next comparison
cp "$LOG_FILE" "$PREV_LOG_FILE"
