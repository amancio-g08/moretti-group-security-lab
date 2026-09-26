# infrastructure/ — AWS lab as code

Terraform and operational scripts for the minimal AWS lab.

**Status:** planned for Phase 4.

Planned layout:

```
infrastructure/
├── terraform/   # VPC, subnets, Security Groups from data/network-matrix.yaml, SSM, logging, budgets
└── scripts/     # lab start / stop / destroy helpers
```

Design constraints: [ADR-002](../docs/adr/ADR-002-cloud-platform.md),
[ADR-003](../docs/adr/ADR-003-single-az.md), [ADR-004](../docs/adr/ADR-004-egress-strategy.md),
[ADR-007](../docs/adr/ADR-007-minimum-footprint.md).
