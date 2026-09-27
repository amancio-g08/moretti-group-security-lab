#!/usr/bin/env bash
# Start the lab: the NAT instance first (hosts need it to reach SSM), then every host.
# shellcheck source=common.sh
source "$(dirname "$0")/common.sh"

nat=$(lab_instances stopped nat)
if [[ -n "$nat" ]]; then
  echo "Starting NAT instance: $nat"
  # shellcheck disable=SC2086
  aws ec2 start-instances --region "$REGION" --instance-ids $nat >/dev/null
  # shellcheck disable=SC2086
  aws ec2 wait instance-running --region "$REGION" --instance-ids $nat
fi

hosts=$(lab_instances stopped host)
if [[ -z "$hosts" ]]; then
  echo "No stopped hosts."
else
  echo "Starting hosts: $hosts"
  # shellcheck disable=SC2086
  aws ec2 start-instances --region "$REGION" --instance-ids $hosts >/dev/null
  # shellcheck disable=SC2086
  aws ec2 wait instance-running --region "$REGION" --instance-ids $hosts
fi
echo "Lab is up. SSM needs 1-2 minutes after boot; the nightly schedule stops everything again."
