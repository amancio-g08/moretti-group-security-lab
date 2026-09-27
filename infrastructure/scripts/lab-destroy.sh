#!/usr/bin/env bash
# Delete the lab (hosts, disks, network). The bootstrap stack (budget, CloudTrail, log bucket)
# is kept unless you also confirm its removal: the logs are evidence for the portfolio.
# shellcheck source=common.sh
source "$(dirname "$0")/common.sh"

read -r -p "Destroy every lab instance, disk and network resource? Type 'destroy': " answer
[[ "$answer" == "destroy" ]] || { echo "Cancelled."; exit 1; }
terraform -chdir="$TF_DIR/lab" destroy

read -r -p "Also destroy the budget, CloudTrail and the log bucket? Type 'destroy-all': " answer
if [[ "$answer" == "destroy-all" ]]; then
  terraform -chdir="$TF_DIR/bootstrap" destroy -var allow_log_bucket_destroy=true
else
  echo "Bootstrap stack kept."
fi
