#!/usr/bin/env bash
# Stop every lab instance. Disks are kept (and still billed); nothing is deleted.
# shellcheck source=common.sh
source "$(dirname "$0")/common.sh"

running=$(lab_instances "pending,running")
if [[ -z "$running" ]]; then
  echo "Nothing is running."
  exit 0
fi
echo "Stopping: $running"
# shellcheck disable=SC2086
aws ec2 stop-instances --region "$REGION" --instance-ids $running >/dev/null
# shellcheck disable=SC2086
aws ec2 wait instance-stopped --region "$REGION" --instance-ids $running
echo "Lab is down."
