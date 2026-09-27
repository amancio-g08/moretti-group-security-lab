# shellcheck shell=bash
# Shared settings for the lab scripts. Sourced, not executed.
# The AWS CLI must be logged in first:  aws sso login --profile <profile>
set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
PROJECT="${LAB_PROJECT:-moretti-group-lab}"
# shellcheck disable=SC2034  # used by lab-destroy.sh
TF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../terraform" && pwd)"

# Instance IDs of the lab in the given state(s), optionally filtered by the Role tag.
lab_instances() {
  local states="$1" role="${2:-}"
  local filters=("Name=tag:Project,Values=${PROJECT}" "Name=instance-state-name,Values=${states}")
  [[ -n "$role" ]] && filters+=("Name=tag:Role,Values=${role}")
  aws ec2 describe-instances --region "$REGION" --filters "${filters[@]}" \
    --query 'Reservations[].Instances[].InstanceId' --output text
}
