# Registros de decisão de arquitetura (ADRs)

**Português** | [English](README.en.md)

Cada ADR registra uma decisão importante do projeto: o contexto, as opções que eu considerei, a
escolha e as consequências. Depois de aceita, uma ADR não é editada; se a decisão mudar, uma ADR
nova substitui a antiga.

As ADRs em si estão em inglês.

| ADR | Decisão | Status |
|---|---|---|
| [001](ADR-001-source-of-truth.md) | A pasta `data/` é a fonte única de verdade | Aceita |
| [002](ADR-002-cloud-platform.md) | AWS para infraestrutura, Entra ID para identidade na nuvem | Aceita |
| [003](ADR-003-single-az.md) | Uma única zona de disponibilidade | Aceita |
| [004](ADR-004-egress-strategy.md) | Saída para a internet controlada pelo Terraform; NAT decidido depois de medir | Aceita |
| [005](ADR-005-lab-vs-enterprise.md) | Packet Tracer é o desenho da empresa; AWS é o laboratório | Aceita |
| [006](ADR-006-identity-evolution.md) | Identidade evolui de AD para híbrido e depois nuvem | Aceita |
| [007](ADR-007-minimum-footprint.md) | Começar com poucas máquinas e crescer por fase | Aceita |
| [008](ADR-008-network-enforcement-points.md) | ACLs no switch core entre VLANs, ASA no perímetro, NAT no roteador de borda | Proposta |

**Status possíveis:** Proposta → Aceita → (Substituída pela ADR-xxx | Descontinuada).

Novas ADRs partem do [TEMPLATE.md](TEMPLATE.md).
