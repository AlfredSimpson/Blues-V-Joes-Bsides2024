#!/bin/bash

# Define the paths after they have been set.
AUDIT_SCRIPT="/path/to/audit.sh"
LOG_FILE="/path/to/user_audit.log"
PREV_LOG_FILE="/path/to/user_audit.log.prev"

# Run the audit script
"$AUDIT_SCRIPT"

# Compare the new log with the previous one
if [ -e "$PREV_LOG_FILE" ]; then
    if ! cmp -s "$LOG_FILE" "$PREV_LOG_FILE"; then
        # Anomalies detected, send message to XXXXXXXXXXXXXXXXX
        {
            echo "Anomaly detected in user audit log:"
            diff "$PREV_LOG_FILE" "$LOG_FILE"
        } | mail -s "User Audit Alert" XXXXXXXXXXXXXXXXX
    fi
else
    # First run, set up the baseline log file
    echo "First run: creating baseline user audit log."
fi

# Update the previous log file for the next comparison
cp "$LOG_FILE" "$PREV_LOG_FILE"
