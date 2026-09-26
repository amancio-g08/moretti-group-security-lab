# Projeto 03 — SOC com Wazuh

**Português** | [English](README.en.md)

Centralização de logs, criação de regras de detecção, triagem de alertas e resposta a incidentes.

**Status:** previsto para a fase 6 (instalação) e para a fase 7 (cenários).

Estrutura planejada:

```
project-03-soc/
├── wazuh/           # notas de instalação, configuração dos agentes, decoders
├── detections/      # regras customizadas e listas (CDB)
├── alerts/          # alertas analisados (verdadeiro ou falso positivo)
├── incidents/       # relatórios de incidente seguindo o ciclo de resposta
└── documentation/   # playbooks e procedimentos
```
