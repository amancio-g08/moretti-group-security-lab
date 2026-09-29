#!/usr/bin/env bash
# Publish the lab's detections to the Wazuh manager on SIEM01: custom rules, account lists
# generated from data/, agent group configurations and the ossec.conf block (AWS module,
# enrollment password, lists). Safe to run again after every change in the repository.
#
#   sudo project-03-soc/wazuh/deploy-ruleset.sh
#
# The new configuration is checked with wazuh-analysisd -t before the manager restarts; if the
# check fails, the previous ossec.conf is restored and nothing is restarted.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
REGION="${AWS_REGION:-us-east-1}"
PROJECT="${LAB_PROJECT:-moretti-group-lab}"
SOC="$(cd "$(dirname "$0")/.." && pwd)"
OSSEC=/var/ossec
BEGIN='<!-- moretti-lab:begin -->'
END='<!-- moretti-lab:end -->'

account="$(aws sts get-caller-identity --query Account --output text --region "$REGION")"
bucket="${PROJECT}-logs-${account}"

install -o root -g wazuh -m 0660 "$SOC/detections/rules/moretti_rules.xml" "$OSSEC/etc/rules/moretti_rules.xml"
for list in "$SOC"/detections/lists/moretti-*; do
  install -o root -g wazuh -m 0660 "$list" "$OSSEC/etc/lists/$(basename "$list")"
done

for group_dir in "$SOC"/agents/groups/*/; do
  group="$(basename "$group_dir")"
  "$OSSEC/bin/agent_groups" -l -q | grep -qx "$group" || "$OSSEC/bin/agent_groups" -a -g "$group" -q
  install -o wazuh -g wazuh -m 0660 "$group_dir/agent.conf" "$OSSEC/etc/shared/$group/agent.conf"
done

cp -p "$OSSEC/etc/ossec.conf" "$OSSEC/etc/ossec.conf.before-moretti"
block="$(sed "s/__LOG_BUCKET__/${bucket}/g" "$SOC/wazuh/moretti-ossec.conf")"
awk -v begin="$BEGIN" -v end="$END" '$0 == begin {skip=1} !skip {print} $0 == end {skip=0}' \
  "$OSSEC/etc/ossec.conf.before-moretti" > "$OSSEC/etc/ossec.conf"
printf '\n%s\n%s\n%s\n' "$BEGIN" "$block" "$END" >> "$OSSEC/etc/ossec.conf"

if ! "$OSSEC/bin/wazuh-analysisd" -t; then
  cp -p "$OSSEC/etc/ossec.conf.before-moretti" "$OSSEC/etc/ossec.conf"
  echo "Configuration check failed: previous ossec.conf restored, manager not restarted." >&2
  exit 1
fi
systemctl restart wazuh-manager
echo "Ruleset deployed (log bucket: $bucket)."
