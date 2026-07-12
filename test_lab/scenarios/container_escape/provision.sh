#!/bin/bash
# Container Escape Scenario - Provisioning Script
set -e
set -x

echo "================================================"
echo "  Container Escape - Vulnerability Provisioning"
echo "================================================"

SHARED=/vagrant/shared/vulnerabilities

apt-get update -qq
apt-get install -y -qq docker.io netcat-openbsd 2>/dev/null || true

bash "$SHARED/docker_exposure.sh"

echo "================================================"
echo "  Container escape provisioning complete!"
echo "================================================"
