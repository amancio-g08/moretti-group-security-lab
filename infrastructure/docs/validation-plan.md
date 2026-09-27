# AWS Lab Validation Plan

Tests to run after the phase 4 deployment ([deployment guide](deployment-guide.md)). Each test
names the rule or control it proves.

> **Status: not executed.** The "Result" column is filled in only with what is actually observed
> in the lab owner's account. The offline Terraform tests
> (`infrastructure/terraform/lab/tests/plan.tftest.hcl`) and the renderer tests in P05 check the
> configuration, not the running environment, and are not a substitute for these tests.

All connection tests target in-scope lab addresses only ([lab safety](../../docs/lab-safety.md)).
`<WS-DEV01>` and `<GUEST01>` are the instance IDs from `terraform output hosts`.

| ID | Control | How | Expected | Result |
|---|---|---|---|---|
| A-01 | CloudTrail | `aws cloudtrail get-trail-status --name moretti-group-lab-trail --query IsLogging` | `true` | Not executed |
| A-02 | Budget | Console → Billing → Budgets | `moretti-group-lab-monthly`, limit US$ 30, 4 alerts | Not executed |
| A-03 | SSM only | `aws ssm start-session --target <WS-DEV01>`, then `hostname` | Shell opens; prints `ws-dev01` | Not executed |
| A-04 | No public IP | `aws ec2 describe-instances --filters Name=tag:Role,Values=host --query 'Reservations[].Instances[].PublicIpAddress'` | Empty list | Not executed |
| A-05 | IMDSv2 | On WS-DEV01: `curl -s -o /dev/null -w '%{http_code}\n' http://169.254.169.254/latest/meta-data/` | `401` (a token is required) | Not executed |
| A-06 | NM-070 via NAT | On WS-DEV01: `curl -sI https://aws.amazon.com \| head -1` | An HTTP status line | Not executed |
| A-07 | NM-004 / NM-060 | On GUEST01: `nc -zv -w 5 10.10.50.10 22` | Times out | Not executed |
| A-08 | Egress limited to the matrix | On WS-DEV01: `nc -zv -w 5 10.10.90.10 22` | Times out (no WS-DEV01 → GUEST01 rule) | Not executed |
| A-09 | Flow Logs | ~10 min after A-07: `aws s3 cp s3://moretti-group-lab-logs-<account>/flowlogs/ ./flowlogs --recursive`, then `gzip -dc $(find flowlogs -name '*.gz') \| grep '10.10.90.10 10.10.50.10'` | Records with action `REJECT` | Not executed |
| A-10 | Nightly stop | The morning after: `aws ec2 describe-instances --filters Name=tag:Project,Values=moretti-group-lab --query 'Reservations[].Instances[].State.Name'` | Every instance `stopped` | Not executed |
| A-11 | Cost | After one week: `infrastructure/scripts/cost-check.sh` | Figures recorded in ADR-004 | Not executed |

Record evidence (terminal output or screenshots) in `infrastructure/docs/evidence/` using the test
ID as the file name. Never include account IDs, e-mail addresses or access portal URLs in
committed evidence: replace them with `<account>`.
