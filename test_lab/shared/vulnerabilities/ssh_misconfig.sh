#!/bin/bash
# SSH Misconfiguration Vulnerabilities
set -e

echo "[*] Configuring SSH vulnerabilities..."

# SSH-101: Protocol 1 (old, insecure protocol)
# Only if sshd supports it (removed in newer versions)
if grep -q "^Protocol" /etc/ssh/sshd_config 2>/dev/null; then
    sed -i 's/^Protocol.*/Protocol 1/' /etc/ssh/sshd_config
else
    echo "Protocol 1" >> /etc/ssh/sshd_config
fi

# SSH-102: Root login with password
sed -i 's/^PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/^#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config

# SSH-103: High MaxAuthTries
sed -i 's/^MaxAuthTries.*/MaxAuthTries 10/' /etc/ssh/sshd_config
sed -i 's/^#MaxAuthTries.*/MaxAuthTries 10/' /etc/ssh/sshd_config

# SSH-104: PermitEmptyPasswords yes
sed -i 's/^PermitEmptyPasswords.*/PermitEmptyPasswords yes/' /etc/ssh/sshd_config
sed -i 's/^#PermitEmptyPasswords.*/PermitEmptyPasswords yes/' /etc/ssh/sshd_config

# SSH-105: No ClientAlive interval
sed -i 's/^ClientAliveInterval.*/ClientAliveInterval 0/' /etc/ssh/sshd_config
sed -i 's/^#ClientAliveInterval.*/ClientAliveInterval 0/' /etc/ssh/sshd_config
sed -i 's/^ClientAliveCountMax.*/ClientAliveCountMax 10/' /etc/ssh/sshd_config
sed -i 's/^#ClientAliveCountMax.*/ClientAliveCountMax 10/' /etc/ssh/sshd_config

# SSH-201: Weak KEX algorithms
if grep -q "^KexAlgorithms" /etc/ssh/sshd_config; then
    sed -i 's/^KexAlgorithms.*/KexAlgorithms diffie-hellman-group1-sha1,diffie-hellman-group14-sha1/' /etc/ssh/sshd_config
else
    echo "KexAlgorithms diffie-hellman-group1-sha1,diffie-hellman-group14-sha1" >> /etc/ssh/sshd_config
fi

# SSH-202: Weak ciphers
if grep -q "^Ciphers" /etc/ssh/sshd_config; then
    sed -i 's/^Ciphers.*/Ciphers 3des-cbc,blowfish-cbc,aes128-cbc/' /etc/ssh/sshd_config
else
    echo "Ciphers 3des-cbc,blowfish-cbc,aes128-cbc" >> /etc/ssh/sshd_config
fi

# SSH-501: X11Forwarding
sed -i 's/^X11Forwarding.*/X11Forwarding yes/' /etc/ssh/sshd_config
sed -i 's/^#X11Forwarding.*/X11Forwarding yes/' /etc/ssh/sshd_config

# SSH-601: Weak MACs
if grep -q "^MACs" /etc/ssh/sshd_config; then
    sed -i 's/^MACs.*/MACs hmac-md5,hmac-sha1,hmac-ripemd160/' /etc/ssh/sshd_config
else
    echo "MACs hmac-md5,hmac-sha1,hmac-ripemd160" >> /etc/ssh/sshd_config
fi

# SSH-603: AllowAgentForwarding
sed -i 's/^AllowAgentForwarding.*/AllowAgentForwarding yes/' /etc/ssh/sshd_config
sed -i 's/^#AllowAgentForwarding.*/AllowAgentForwarding yes/' /etc/ssh/sshd_config

# SSH-105/606: No ClientAlive timeout
sed -i 's/^TCPKeepAlive.*/TCPKeepAlive yes/' /etc/ssh/sshd_config
sed -i 's/^#TCPKeepAlive.*/TCPKeepAlive yes/' /etc/ssh/sshd_config

systemctl restart sshd
echo "[+] SSH vulnerabilities configured"
