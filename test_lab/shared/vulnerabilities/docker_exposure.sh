#!/bin/bash
# Container and Docker Misconfigurations
set -e

echo "[*] Configuring container vulnerabilities..."

# Install Docker if not present
if ! command -v docker &>/dev/null; then
    apt-get install -y -qq docker.io 2>/dev/null || true
fi

# CTN-101: Expose Docker socket to non-root
chmod 666 /var/run/docker.sock 2>/dev/null || true

# CTN-102: Docker daemon TCP exposure
mkdir -p /etc/docker
cat > /etc/docker/daemon.json << 'DOCKERD'
{
  "hosts": ["tcp://0.0.0.0:2375", "unix:///var/run/docker.sock"],
  "iptables": false,
  "userns-remap": ""
}
DOCKERD

# CTN-201: Run a privileged container
docker pull alpine:latest 2>/dev/null || true
docker run -d --name privileged-test --privileged alpine:latest sleep 3600 2>/dev/null || true

# CTN-202: Host network namespace
docker run -d --name host-net-test --network host alpine:latest sleep 3600 2>/dev/null || true

# CTN-203: Host PID namespace
docker run -d --name host-pid-test --pid host alpine:latest sleep 3600 2>/dev/null || true

# CTN-204: Host filesystem mount
docker run -d --name host-mount-test -v /:/host alpine:latest sleep 3600 2>/dev/null || true

# CTN-301: Root containers (already root by default)

# CTN-401: Old images (use old tag)
docker pull alpine:3.8 2>/dev/null || true

# CTN-402: Unsigned images (Docker Hub images are not signed by default)
docker pull nginx:latest 2>/dev/null || true

# CTN-303: Extra capabilities
docker run -d --name extra-caps-test --cap-add SYS_ADMIN --cap-add NET_ADMIN alpine:latest sleep 3600 2>/dev/null || true

# CTN-305: Writable rootfs
docker run -d --name writable-rootfs-test --read-only=false alpine:latest sleep 3600 2>/dev/null || true

echo "[+] Container vulnerabilities configured"
