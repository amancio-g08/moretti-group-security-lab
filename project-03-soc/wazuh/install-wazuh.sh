#!/usr/bin/env bash
# Install Wazuh (manager, indexer and dashboard on one host) on SIEM01.
#
# Run as root on SIEM01, in an SSM session, from a clone of this repository:
#   sudo WAZUH_RELEASE=<major.minor> project-03-soc/wazuh/install-wazuh.sh
# WAZUH_RELEASE is the current release shown in the Wazuh quickstart (for example 4.12).
#
# Passwords never reach the terminal or the disk: the admin and API passwords go to SSM
# Parameter Store (SecureString) and the installer's password bundle is deleted. The dashboard
# is reached only through SSM port forwarding (see the SOC design document).
set -euo pipefail

: "${WAZUH_RELEASE:?set WAZUH_RELEASE to the current release in the Wazuh quickstart, e.g. 4.12}"
[[ "$WAZUH_RELEASE" =~ ^[0-9]+\.[0-9]+$ ]] || { echo "WAZUH_RELEASE must look like 4.12" >&2; exit 1; }
[[ $EUID -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
[[ "$(hostname)" == "siem01" ]] || { echo "Run on SIEM01 (this is $(hostname))." >&2; exit 1; }

REGION="${AWS_REGION:-us-east-1}"
PREFIX="${PARAMETER_PREFIX:-/moretti-group-lab/wazuh}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"
HERE="$(cd "$(dirname "$0")" && pwd)"

command -v aws >/dev/null || snap install aws-cli --classic

put_secret() {  # name value [--overwrite]
  aws ssm put-parameter --region "$REGION" --name "$PREFIX/$1" --type SecureString \
    --value "$2" ${3:+"$3"} >/dev/null
}

get_secret() {
  aws ssm get-parameter --region "$REGION" --with-decryption --name "$PREFIX/$1" \
    --query Parameter.Value --output text 2>/dev/null || true
}

if [[ ! -d /var/ossec ]]; then
  workdir="$(mktemp -d)"
  trap 'rm -rf "$workdir"' EXIT
  cd "$workdir"
  curl -sSfO "https://packages.wazuh.com/${WAZUH_RELEASE}/wazuh-install.sh"
  bash ./wazuh-install.sh -a --install-dependencies

  # Keep only what the lab needs from the bundle, in Parameter Store.
  passwords="$(tar -O -xf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt)"
  field() {  # user_key user_name password_key
    awk -v u="$1: '$2'" -v p="$3" 'index($0, u) {found=1; next} found && index($0, p) {
      sub(/^[^:]*: *'"'"'/, ""); sub(/'"'"' *$/, ""); print; exit}' <<<"$passwords"
  }
  put_secret admin-password "$(field indexer_username admin indexer_password)" --overwrite
  put_secret api-password "$(field api_username wazuh api_password)" --overwrite
  unset passwords
  shred -u wazuh-install-files.tar
else
  echo "Wazuh is already installed; skipping the installer."
fi

# Agent enrollment password: reuse the stored one, so agents enrolled earlier keep working.
enrollment="$(get_secret enrollment-password)"
if [[ -z "$enrollment" ]]; then
  enrollment="$(openssl rand -base64 32)"
  put_secret enrollment-password "$enrollment"
fi
umask 027
printf '%s\n' "$enrollment" > /var/ossec/etc/authd.pass
chown root:wazuh /var/ossec/etc/authd.pass
unset enrollment

# Alert retention that fits the 40 GB disk (ADR-010). Applies to indices created from now on.
admin_password="$(get_secret admin-password)"
# The password goes through a file descriptor, never on the command line.
curl -sS -K <(printf 'user = "admin:%s"\n' "$admin_password") -k -o /dev/null -w 'retention policy: HTTP %{http_code}\n' \
  -X PUT "https://localhost:9200/_plugins/_ism/policies/moretti-retention" \
  -H 'Content-Type: application/json' -d @- <<JSON || true
{"policy": {"description": "Delete Wazuh alerts after ${RETENTION_DAYS} days",
  "default_state": "hot",
  "states": [
    {"name": "hot", "actions": [], "transitions": [{"state_name": "delete", "conditions": {"min_index_age": "${RETENTION_DAYS}d"}}]},
    {"name": "delete", "actions": [{"delete": {}}], "transitions": []}],
  "ism_template": [{"index_patterns": ["wazuh-alerts-*"], "priority": 100}]}}
JSON
unset admin_password

"$HERE/deploy-ruleset.sh"
echo "Done. Dashboard: aws ssm start-session --target <SIEM01 id> --document-name AWS-StartPortForwardingSession --parameters portNumber=443,localPortNumber=8443"
