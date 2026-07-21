#!/bin/bash
# Secret and Credential Exposure
set -e

echo "[*] Configuring secret exposure vulnerabilities..."

# SECR-101: AWS keys in various locations
cat > /home/ubuntu/.aws/credentials << 'AWS'
[default]
aws_access_key_id = AKIAXXXXXXXXXXXXXX
aws_secret_access_key = XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
AWS

mkdir -p /home/ubuntu/.aws
chmod 600 /home/ubuntu/.aws/credentials

# AWS key in config file
cat > /opt/app/config.ini << 'INI'
[aws]
aws_access_key_id = AKIAXXXXXXXXXXXXXX
aws_secret_access_key = XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
region = us-east-1
INI

# SECR-202: .env files
cat > /opt/app/.env << 'ENV'
DATABASE_URL=postgres://admin:supersecret@localhost:5432/prod
SECRET_KEY=super-secret-key-12345
API_KEY=sk_test_xxxxxxxxxxxxxxxxxxxxx
AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXXXXX
ENV

# SECR-203: API keys in source code
cat > /opt/app/api_config.py << 'PYTHON'
API_KEYS = {
    "stripe": "sk_test_XXXXXXXXXXXXXXXXXXXXXXXXXXX",
    "github": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
}
PYTHON

# SECR-301: Exposed SSH private key
mkdir -p /home/ubuntu/.ssh
chmod 700 /home/ubuntu/.ssh
cat > /home/ubuntu/.ssh/id_rsa << 'KEY'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA6NF8ix3g3H8zBKE/dBG3BqH8vZgL/TM7S1E7OQ+LzJQfVhCgYx
R5QzYHJx5M8EdPQ0FqJRHqJqXJUkJEcbRGFGcBK6uQHQEh/SC/L4mSq7gCwI4gAAgCkF
Sf2prmNQJRz3C8WJwLkQcJo1YB6ZtK4gGQi5xCyA1sGJIQj8C8I7YJ0mBZ8QSUqHc3U
-----END OPENSSH PRIVATE KEY-----
KEY
chmod 600 /home/ubuntu/.ssh/id_rsa

# SECR-302: Weak SSH key type (DSA)
cat > /home/ubuntu/.ssh/id_dsa << 'KEY2'
-----BEGIN DSA PRIVATE KEY-----
MIIBvAIBAAKBgQC8l3g6WqZgM1EdqGZqJQJmFfz6WrGh4K9SqGqY3H8XQgD1Lg
-----END DSA PRIVATE KEY-----
KEY2
chmod 600 /home/ubuntu/.ssh/id_dsa

# SECR-401: Database credentials in config
cat > /opt/app/database.yml << 'DBYML'
production:
  adapter: postgresql
  database: myapp_prod
  username: admin
  password: MyS3cur3P@ssw0rd!
  host: prod-db.example.com

staging:
  adapter: mysql2
  database: myapp_staging
  username: deploy
  password: password123
  host: staging-db.example.com
DBYML

# GitHub token in file
cat > /opt/app/.github_token << 'GHTOKEN'
ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
GHTOKEN

# SECR-601: GitLab token
echo "glpat-xxxxxxxxxxxxxxxxxxxx" > /opt/app/.gitlab_token

# SECR-602: Slack token (test-only, non-functional format)
echo "FAKE-SLACK-TOKEN-FOR-TESTING-ONLY" > /opt/app/.slack_token

# SECR-605: Docker credentials
mkdir -p /home/ubuntu/.docker
cat > /home/ubuntu/.docker/config.json << 'DOCKERCFG'
{
  "auths": {
    "https://index.docker.io/v1/": {
      "auth": "dXNlcm5hbWU6cGFzc3dvcmQXXXX"
    }
  }
}
DOCKERCFG

# SECR-608: Password in source code
cat > /opt/app/mail.py << 'MAILPY'
import smtplib

def send_email(to, subject, body):
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.login('admin@example.com', 'P@ssw0rd!123')
    server.sendmail('admin@example.com', to, body)
    server.quit()
MAILPY

echo "[+] Secret exposure vulnerabilities configured"
