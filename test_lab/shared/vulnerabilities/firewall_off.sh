#!/bin/bash
# Firewall Hardening Off
set -e

echo "[*] Disabling firewall..."

# FW-101: Disable firewall
ufw disable 2>/dev/null || true

# FW-201: Set iptables default policy to ACCEPT
iptables -P INPUT ACCEPT 2>/dev/null || true
iptables -P FORWARD ACCEPT 2>/dev/null || true
iptables -P OUTPUT ACCEPT 2>/dev/null || true

# Flush all rules
iptables -F 2>/dev/null || true
ip6tables -F 2>/dev/null || true

# FW-102: No rules protecting SSH (already accessible)

echo "[+] Firewall disabled"
