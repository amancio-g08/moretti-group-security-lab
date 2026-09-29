#!/usr/bin/env bash
# Install and enroll the Wazuh agent on a Linux lab host (WS-DEV01, later APP-FIN01).
#
# Run as root on the host, in an SSM session, from a clone of this repository:
#   sudo WAZUH_VERSION=<x.y.z> project-03-soc/agents/install-agent-linux.sh
# WAZUH_VERSION is the manager's version: on SIEM01, /var/ossec/bin/wazuh-control info.
# An agent must never be newer than its manager, so the package is also held.
#
# The enrollment password is read from SSM Parameter Store (the host's role may read only that
# parameter) and written to the agent's authd.pass, never passed on the command line.
set -euo pipefail

: "${WAZUH_VERSION:?set WAZUH_VERSION to the manager version, e.g. 4.12.0}"
[[ $EUID -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
REGION="${AWS_REGION:-us-east-1}"
MANAGER="${WAZUH_MANAGER_IP:-10.10.70.10}"   # SIEM01 (data/assets.yaml)
GROUP="${WAZUH_AGENT_GROUP:-linux}"
PARAMETER="${ENROLLMENT_PARAMETER:-/moretti-group-lab/wazuh/enrollment-password}"

command -v aws >/dev/null || snap install aws-cli --classic

if [[ ! -f /usr/share/keyrings/wazuh.gpg ]]; then
  curl -sSf https://packages.wazuh.com/key/GPG-KEY-WAZUH |
    gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
  chmod 644 /usr/share/keyrings/wazuh.gpg
fi
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  > /etc/apt/sources.list.d/wazuh.list
apt-get update -q

WAZUH_MANAGER="$MANAGER" WAZUH_AGENT_GROUP="$GROUP" WAZUH_AGENT_NAME="$(hostname)" \
  apt-get install -y -q "wazuh-agent=${WAZUH_VERSION}-1"
apt-mark hold wazuh-agent

umask 027
aws ssm get-parameter --region "$REGION" --with-decryption --name "$PARAMETER" \
  --query Parameter.Value --output text > /var/ossec/etc/authd.pass
chown root:wazuh /var/ossec/etc/authd.pass

systemctl daemon-reload
systemctl enable --now wazuh-agent
echo "Agent installed. On SIEM01, /var/ossec/bin/agent_control -l should list $(hostname) as Active."
