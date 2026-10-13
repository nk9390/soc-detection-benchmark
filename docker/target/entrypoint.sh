#!/bin/bash

# Start rsyslog daemon directly
rsyslogd || echo "[!] rsyslog failed to start"

# Start auditd daemon directly
auditd || echo "[!] auditd failed to start"

# Wait for auditd to be ready
sleep 2

# Load audit rules
auditctl -R /etc/audit/rules.d/soc-benchmark.rules 2>/dev/null || echo "[!] Failed to load audit rules"

echo "[*] Target container initialized"
echo "[*] Atomic Red Team ready at /opt/atomic-red-team"

# Execute CMD
exec "$@"
