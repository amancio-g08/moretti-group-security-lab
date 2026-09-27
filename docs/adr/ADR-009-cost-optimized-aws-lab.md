# ADR-009: Cost-optimized AWS lab: hosts per phase, Graviton, Spot and a NAT instance

- **Status:** Accepted
- **Date:** 2026-09-27
- **Related:** ADR-003, ADR-004, ADR-007

## Context

The first estimate for the AWS lab, with the five hosts of ADR-007 running on demand behind a NAT
Gateway, was about US$ 0.29 per running hour plus about US$ 11 per month of disks: roughly
US$ 23 for 40 hours a month, and about US$ 220 if the lab were left running for a whole month.
The lab owner asked for a cheaper design before any resource is created.

These figures are **estimates from on-demand list prices** (us-east-1), not measurements. Measured
costs are recorded in ADR-004 once the lab has run.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| A. Five hosts on demand + NAT Gateway (initial design) | No maintenance of the egress path; no interruptions | Highest cost; the NAT Gateway bills every hour it exists |
| B. Deploy each host only in the phase that needs it | Early phases cost almost nothing | Hosts appear over time; the lab is incomplete until phase 7 |
| C. NAT instance (t4g.nano) instead of NAT Gateway | About US$ 0.01/h instead of about US$ 0.05/h; can be stopped | One more host to patch; single point of failure; needs a public IP |
| D. Graviton (arm64, t4g) for Linux hosts | About 20% cheaper than t3 | Windows cannot run on it; software must support arm64 |
| E. Spot for lab hosts | About 60–70% cheaper | AWS can stop a host with two minutes' notice |
| F. Run everything on the operator's Mac | No AWS cost | Windows Server is not supported on Apple Silicon; not enough RAM for Wazuh; loses the cloud controls that the portfolio demonstrates |
| G. A managed backend platform such as Supabase | Free tier | No VMs, VPC, Security Groups, Flow Logs or CloudTrail: cannot host the lab |

## Decision

B + C + D + E, in region **us-east-1**:

- **Hosts per phase.** `aws_phase` in `data/assets.yaml` decides when each host exists, and the
  Terraform variable `lab_phase` deploys every host up to that phase. Phase 4: WS-DEV01 and
  GUEST01. Phase 5: DC01 and WS-FIN01. Phase 6: SIEM01. Phase 7: APP-FIN01.
- **NAT instance** (t4g.nano, Amazon Linux 2023) in a small public TRANSIT subnet. This decides
  the NAT option left open in ADR-004. It is the **only** instance with a public IP, which the lab
  safety rules require an ADR to justify: it must reach the internet to translate outbound
  traffic. It accepts connections only from the VPC, and only on the ports that the matrix allows
  towards the internet.
- **Graviton** for every Linux host; Windows hosts stay on t3.
- **Spot** (persistent, stop on interruption) for every host except **DC01**: interrupting the
  domain controller in the middle of a session would break every domain member.
- **Nightly stop** of every instance by EventBridge Scheduler, on top of the budget alerts.
- **GUEST01 runs Ubuntu Server** with offensive tools installed when a scenario needs them,
  instead of the Kali Linux Marketplace image, which requires accepting a Marketplace
  subscription in the account.
- **Terraform state stays on the operator's machine.** No remote backend to pay for or secure;
  the state never enters Git.
- **Systems Manager egress (NM-072).** Hosts are managed only through AWS Systems Manager, whose
  endpoints are public HTTPS services. Security Groups cannot filter by hostname, so every AWS host
  may open HTTPS to any address while egress is enabled.

## Rationale

The largest saving comes from not running hosts before they are needed; the others cut the
hourly price of what does run. Together they bring the estimate for the heaviest phases to about
US$ 0.12–0.17 per running hour plus about US$ 8 per month of disks, and phase 4 to a few dollars
per month. The trade-offs are operational (interruptions, one more host to patch), not weaker
segmentation: the Security Groups are the same in every option.

## Consequences

- Positive: early phases cost almost nothing; the heaviest phases cost about half of option A.
- Negative / accepted risks:
  - A Spot host can be stopped during a session; it is started again with `lab-up.sh`.
  - The NAT instance must be patched and is a single point of failure for egress and SSM access.
  - NM-072 opens HTTPS to any destination for every AWS host, wider than the Packet Tracer policy
    (NM-071). VPC interface endpoints for Systems Manager (ADR-004, option C) would remove it at
    an extra hourly cost.
  - DC01 uses 56 of the 60 inbound rules a Security Group allows by default. A new rule towards
    DC01 needs a quota increase or a prefix list.
- Follow-up work: measure real costs after the first week (ADR-004); confirm that Wazuh runs on
  arm64 before phase 6.

## Revisit when

Measured costs differ materially from these estimates, Spot interruptions disrupt the scenarios,
or the lab needs egress that is permanent or narrower than NM-072.
