# Projeto 01 — Rede corporativa (Packet Tracer)

**Português** | [English](README.en.md)

A rede completa da Moretti Group: segmentação em VLANs, ACLs entre VLANs, firewall de perímetro,
DMZ e hardening dos equipamentos, tudo seguindo o `data/network-matrix.yaml`.

**Status:** previsto para a fase 2.

Estrutura planejada:

```
project-01-network/
├── packet-tracer/   # arquivo .pkt da topologia
├── configs/         # configurações dos equipamentos (switches, core, firewall, roteador)
└── documentation/   # endereçamento, VLANs, justificativa das ACLs, hardening, pontos de ataque, testes
```

A relação entre esta rede e o laboratório na AWS está explicada na
[ADR-005](../docs/adr/ADR-005-lab-vs-enterprise.md).
