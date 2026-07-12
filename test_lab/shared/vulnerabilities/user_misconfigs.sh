#!/bin/bash
# User and Authentication Misconfigurations
set -e

echo "[*] Configuring user vulnerabilities..."

# USR-201: Create user with empty password
useradd -M -s /bin/bash vulnuser 2>/dev/null || true
passwd -d vulnuser 2>/dev/null || true

# USR-101: Duplicate UID 0
useradd -M -s /bin/bash -o -u 0 duperoot 2>/dev/null || true

# USR-104: Disabled account with valid shell
useradd -M -s /bin/bash disableduser 2>/dev/null || true
passwd -l disableduser 2>/dev/null || true

# USR-105: Expired password
useradd -M -s /bin/bash expireduser 2>/dev/null || true
passwd -e expireduser 2>/dev/null || true

# USR-103: Duplicate UIDs
useradd -M -s /bin/bash -u 5005 dupuser1 2>/dev/null || true
useradd -M -s /bin/bash -u 5005 dupuser2 2>/dev/null || true

# USR-402: No password for sudo
echo "nopassuser ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/vuln 2>/dev/null || true
echo "vulnuser ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/vuln 2>/dev/null || true

# USR-401: Unauthorized sudo member
useradd -M -s /bin/bash badsudo 2>/dev/null || true
usermod -aG sudo badsudo 2>/dev/null || true

# USR-403: Long sudo timestamp timeout
echo "Defaults timestamp_timeout=60" >> /etc/sudoers.d/timeout 2>/dev/null || true

# USR-501: Service account with shell
usermod -s /bin/bash nobody 2>/dev/null || true
usermod -s /bin/bash daemon 2>/dev/null || true

# PWD-101: Weak password policy
cat > /etc/security/pwquality.conf << 'PWQUALITY'
# WEAK password quality - FOR TESTING ONLY
minlen = 6
minclass = 1
maxrepeat = 3
dcredit = 0
ucredit = 0
lcredit = 0
ocredit = 0
difok = 0
PWQUALITY

# PWD-201: No password history
if grep -q "^password.*pam_unix.so" /etc/pam.d/common-password; then
    sed -i 's/remember=[0-9]*//' /etc/pam.d/common-password
fi

# PWD-202: Min age 0 (can change immediately)
chage -m 0 vulnuser 2>/dev/null || true

# PWD-203: Max age 99999 (never expires)
chage -M 99999 vulnuser 2>/dev/null || true

# PWD-204: No expiry warning
chage -W 0 vulnuser 2>/dev/null || true

# PWD-301: No account lockout
# Remove pam_tally2 or pam_faillock if present

echo "[+] User vulnerabilities configured"
