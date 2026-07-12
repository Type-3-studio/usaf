#!/bin/bash
# SUID/SGID Backdoors and Permission Issues
set -e

echo "[*] Configuring permission vulnerabilities..."

# PRM-101: Setup SUID backdoors
cp /bin/bash /usr/local/bin/.bashdb 2>/dev/null || true
chmod u+s /usr/local/bin/.bashdb 2>/dev/null || true
cp /bin/sh /usr/local/bin/shell 2>/dev/null || true
chmod u+s /usr/local/bin/shell 2>/dev/null || true

# PRM-201: World-writable sensitive files
chmod 777 /etc/passwd 2>/dev/null || true
chmod 777 /etc/shadow 2>/dev/null || true
chmod 777 /etc/ssh/sshd_config 2>/dev/null || true
chmod 777 /usr/local/bin/.bashdb 2>/dev/null || true

# PRM-301: SGID backdoor
cp /usr/bin/find /usr/local/bin/.finddb 2>/dev/null || true
chmod g+s /usr/local/bin/.finddb 2>/dev/null || true

# PRM-304: World-writable directory in PATH
mkdir -p /tmp/exploit_path
chmod 777 /tmp/exploit_path
echo '#!/bin/bash' > /tmp/exploit_path/sysctl
echo 'id' >> /tmp/exploit_path/sysctl
chmod +x /tmp/exploit_path/sysctl
export PATH="/tmp/exploit_path:$PATH"

# PRM-303: Missing sticky bit
mkdir -p /tmp/not_sticky
chmod 777 /tmp/not_sticky

# FS-601: Sensitive file permissions
chmod 644 /etc/shadow 2>/dev/null || true
chmod 644 /etc/gshadow 2>/dev/null || true

# FS-402: World-writable directories in root
mkdir -p /root_writable
chmod 777 /root_writable

echo "[+] Permission vulnerabilities configured"
