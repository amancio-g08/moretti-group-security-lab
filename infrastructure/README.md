# infrastructure/ — Laboratório na AWS como código

**Português** | [English](README.en.md)

Terraform e scripts para subir, desligar e destruir o laboratório mínimo na AWS.

**Status:** previsto para a fase 4.

Estrutura planejada:

```
infrastructure/
├── terraform/   # VPC, sub-redes, Security Groups gerados a partir de data/network-matrix.yaml, SSM, logs, orçamento
└── scripts/     # ligar / desligar / destruir o lab
```

As decisões que limitam esta parte estão nas ADRs
[002](../docs/adr/ADR-002-cloud-platform.md), [003](../docs/adr/ADR-003-single-az.md),
[004](../docs/adr/ADR-004-egress-strategy.md) e [007](../docs/adr/ADR-007-minimum-footprint.md).
