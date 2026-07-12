#!/bin/bash
# Secrets Exposed Scenario - Provisioning Script
set -e
set -x

echo "================================================"
echo "  Secrets Exposed - Vulnerability Provisioning"
echo "================================================"

SHARED=/vagrant/shared/vulnerabilities
mkdir -p /opt/app

bash "$SHARED/secret_injection.sh"

echo "================================================"
echo "  Secrets exposure provisioning complete!"
echo "================================================"
