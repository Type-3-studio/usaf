#!/bin/bash
# Suspicious Network Configuration
set -e

echo "[*] Configuring network vulnerabilities..."

# NET-301: Set unexpected DNS servers
cat > /etc/resolv.conf << 'RESOLV'
nameserver 8.8.8.8
nameserver 1.1.1.1
nameserver 192.168.1.1
RESOLV

# NET-302: Modify /etc/hosts with suspicious entries
cat >> /etc/hosts << 'HOSTS'
127.0.0.1       paypal.com
127.0.0.1       google.com
127.0.0.1       banking.example.com
192.168.1.100   update-server.internal
HOSTS

# NET-102: Start a sensitive listening service
nc -l -p 3306 -e /bin/true & 2>/dev/null || true  # Fake MySQL
nc -l -p 5432 -e /bin/true & 2>/dev/null || true  # Fake PostgreSQL
nc -l -p 6379 -e /bin/true & 2>/dev/null || true  # Fake Redis

# NET-201: Enable promiscuous mode
ip link set eth0 promisc on 2>/dev/null || true

# NET-203: Enable ALLMULTI
ip link set eth0 allmulti on 2>/dev/null || true

# BOOT-101: Disable secure boot (simulate in kernel param)
echo "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet splash\"" >> /etc/default/grub.d/vuln.cfg 2>/dev/null || true

# No auditd
service auditd stop 2>/dev/null || true
systemctl stop auditd 2>/dev/null || true
systemctl disable auditd 2>/dev/null || true

echo "[+] Network vulnerabilities configured"
