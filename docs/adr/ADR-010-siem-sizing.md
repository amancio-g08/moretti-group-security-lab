# ADR-010: SIEM01 on x86_64, below the recommended size, with 14-day retention

- **Status:** Accepted
- **Date:** 2026-09-29
- **Related:** ADR-007, ADR-009

## Context

ADR-009 chose Graviton (arm64) for every Linux host and left one follow-up: confirm that Wazuh
runs on arm64 before phase 6. The Wazuh documentation repository was checked on 2026-09-29:

- the `master` branch of the quickstart says the central components (server, indexer, dashboard)
  install on **x86_64/AMD64** only;
- the `main` branch, which carries pre-release documentation, says x86_64 **or** AArch64/ARM64.

It could not be determined from here which page describes the release that will be installed.
The same quickstart recommends **4 vCPU and 8 GiB** of RAM for 1 to 25 agents and 50 GB of
storage for 90 days of alerts. The lab has 3 agents in phase 6 (DC01, WS-FIN01, WS-DEV01).

## Options considered

| Option | Pros | Cons |
|---|---|---|
| A. t4g.large (arm64, 2 vCPU, 8 GiB) as in ADR-009 | Cheapest | May not be supported by the release installed; found out only at install time |
| B. t3.large (x86_64, 2 vCPU, 8 GiB), 40 GB disk, 14-day retention | Supported by both documentation pages; about US$ 0.005/h more on Spot | Half the recommended vCPUs; shorter alert history |
| C. t3.xlarge (x86_64, 4 vCPU, 16 GiB) | Meets the recommendation | About twice the SIEM cost |

## Decision

Option B: SIEM01 runs on **t3.large** (x86_64) on Spot, with a **40 GB** disk and an index
lifecycle policy that deletes alert indices after **14 days**. The agents on Linux hosts stay on
arm64, which the Wazuh agent packages support.

## Rationale

Supportability matters more than a few cents an hour: an unsupported architecture would stop
phase 6 at installation. Three agents produce far less data than the 25-agent sizing assumes, so
2 vCPU is expected to be enough. This is an expectation, not a measurement, and it is checked
during validation.

## Consequences

- Positive: the install follows the documented path; the cost stays close to ADR-009.
- Negative / accepted risks: the dashboard and indexer may be slow under load; alerts older than
  14 days are gone (evidence of a scenario must be exported within that window).
- Follow-up: record CPU and memory use during validation (W-10); move to option C if the manager
  or indexer cannot keep up.

## Revisit when

The installed release supports arm64 officially, or the validation shows SIEM01 cannot keep up.
