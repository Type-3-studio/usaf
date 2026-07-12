#!/bin/bash
# Insecure Server Scenario - Provisioning Script
# Sets up 15+ known vulnerabilities for USAF validation
set -e
set -x

echo "================================================"
echo "  Insecure Server - Vulnerability Provisioning"
echo "================================================"

SHARED=/vagrant/shared/vulnerabilities
if [ ! -d "$SHARED" ]; then
    echo "[-] Shared directory not mounted. Copying files..."
    mkdir -p /tmp/vulns
    cp -r /vagrant/shared/vulnerabilities /tmp/vulns/
    SHARED=/tmp/vulns/vulnerabilities
fi

# Update package lists
apt-get update -qq

# Install necessary tools
apt-get install -y -qq netcat-openbsd curl iptables ufw 2>/dev/null || true

# === APPLY VULNERABILITIES ===

bash "$SHARED/ssh_misconfig.sh"
bash "$SHARED/kernel_weak_params.sh"
bash "$SHARED/user_misconfigs.sh"
bash "$SHARED/firewall_off.sh"
bash "$SHARED/network_suspicious.sh"
bash "$SHARED/suid_backdoor.sh"
bash "$SHARED/ld_preload_injection.sh"
bash "$SHARED/cron_persistence.sh"
bash "$SHARED/systemd_trojan.sh"

# Install and start some services to trigger SVC checks
apt-get install -y -qq apache2 mysql-server 2>/dev/null || true
systemctl start apache2 2>/dev/null || true
systemctl start mysql 2>/dev/null || true

# Install old packages for PKG checks
apt-get install -y -qq telnet rsh-client talk 2>/dev/null || true

echo "================================================"
echo "  Vulnerability provisioning complete!"
echo "  Run: usaf scan --format json"
echo "================================================"
