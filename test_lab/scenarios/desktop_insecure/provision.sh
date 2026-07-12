#!/bin/bash
# Insecure Desktop Scenario - Provisioning Script
set -e
set -x

echo "================================================"
echo "  Insecure Desktop - Vulnerability Provisioning"
echo "================================================"

SHARED=/vagrant/shared/vulnerabilities

apt-get update -qq

# Install legacy/insecure services for CMP checks
apt-get install -y -qq \
    telnet rsh-client talk whoopsie cups avahi-daemon \
    nfs-common rpcbind x11-utils xserver-xorg-core \
    python3-pip 2>/dev/null || true

# Start legacy services
systemctl start whoopsie 2>/dev/null || true
systemctl start cups 2>/dev/null || true
systemctl start avahi-daemon 2>/dev/null || true
systemctl start rpcbind 2>/dev/null || true

bash "$SHARED/user_misconfigs.sh"
bash "$SHARED/firewall_off.sh"

# World-writable PATH directories (CMP-210 / PRM-304)
chmod 777 /usr/local/bin
chmod 777 /usr/bin

# Create world-writable cron directories
chmod 777 /etc/cron.d

# Missing sticky bit on /tmp
chmod -t /tmp 2>/dev/null || true

echo "================================================"
echo "  Insecure desktop provisioning complete!"
echo "================================================"
