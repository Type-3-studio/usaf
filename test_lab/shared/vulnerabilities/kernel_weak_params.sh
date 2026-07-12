#!/bin/bash
# Weak Kernel Parameters
set -e

echo "[*] Configuring weak kernel parameters..."

# KERN-101: Disable ASLR
echo 0 > /proc/sys/kernel/randomize_va_space

# KERN-201: Disable ptrace restriction
echo 0 > /proc/sys/kernel/yama/ptrace_scope

# KERN-301: Enable core dumps
echo 0 > /proc/sys/fs/suid_dumpable
ulimit -c unlimited

# KERN-401: Enable module auto-loading
echo 1 > /proc/sys/kernel/modules_disabled 2>/dev/null || true
# Actually we want module loading ON (vulnerable)
echo 0 > /proc/sys/kernel.modules_disabled 2>/dev/null || true

# KERN-451: Unprivileged BPF
echo 1 > /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || true
# Actually we want unprivileged BPF enabled (vulnerable)
echo 0 > /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || true

# KERN-511: Disable link protections
echo 0 > /proc/sys/fs/protected_hardlinks 2>/dev/null || true
echo 0 > /proc/sys/fs/protected_symlinks 2>/dev/null || true

# KERN-852: Disable IOMMU
echo 0 > /proc/sys/kernel/io_DMA_restriction 2>/dev/null || true

# KERN-552: Perf event paranoid
echo -1 > /proc/sys/kernel/perf_event_paranoid 2>/dev/null || true

# NET-401: Weak network sysctl
echo 1 > /proc/sys/net/ipv4/conf/all/accept_source_route
echo 1 > /proc/sys/net/ipv4/conf/all/accept_redirects
echo 1 > /proc/sys/net/ipv4/conf/all/send_redirects
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 0 > /proc/sys/net/ipv4/tcp_syncookies

# NET-402: IPv6 router advertisements
echo 1 > /proc/sys/net/ipv6/conf/all/accept_ra 2>/dev/null || true
echo 1 > /proc/sys/net/ipv6/conf/all/autoconf 2>/dev/null || true

# Make some persistent via sysctl.conf
cat >> /etc/sysctl.conf << 'SYSCONF'
# WEAK SETTINGS - FOR TESTING ONLY
kernel.randomize_va_space = 0
kernel.yama.ptrace_scope = 0
fs.suid_dumpable = 0
kernel.unprivileged_bpf_disabled = 0
fs.protected_hardlinks = 0
fs.protected_symlinks = 0
kernel.perf_event_paranoid = -1
net.ipv4.conf.all.accept_source_route = 1
net.ipv4.conf.all.accept_redirects = 1
net.ipv4.conf.all.send_redirects = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.tcp_syncookies = 0
SYSCONF

echo "[+] Weak kernel parameters configured"
