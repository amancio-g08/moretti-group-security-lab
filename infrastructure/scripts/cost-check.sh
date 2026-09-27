#!/usr/bin/env bash
# Month-to-date cost per service, from Cost Explorer. Each call costs US$ 0.01.
# shellcheck source=common.sh
source "$(dirname "$0")/common.sh"

start=$(date +%Y-%m-01)
end=$(date -v+1d +%Y-%m-%d 2>/dev/null || date -d tomorrow +%Y-%m-%d)  # macOS, then GNU date

# shellcheck disable=SC2016  # backticks are JMESPath literals, not shell
aws ce get-cost-and-usage --region us-east-1 \
  --time-period "Start=${start},End=${end}" \
  --granularity MONTHLY --metrics UnblendedCost \
  --group-by Type=DIMENSION,Key=SERVICE \
  --query 'ResultsByTime[0].Groups[?to_number(Metrics.UnblendedCost.Amount) > `0`].[Keys[0], Metrics.UnblendedCost.Amount]' \
  --output table
