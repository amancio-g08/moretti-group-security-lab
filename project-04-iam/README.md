# Projeto 04 — Gestão de identidades e acessos (IAM)

**Português** | [English](README.en.md)

Controle de acesso por função e menor privilégio na Moretti Group, começando no Active Directory,
passando por identidade híbrida e chegando no Entra ID
([ADR-006](../docs/adr/ADR-006-identity-evolution.md)).

**Status:** previsto para a fase 5 (AD) e para a fase 8 (Entra ID).

Estrutura planejada:

```
project-04-iam/
├── users/           # criação de usuários a partir do data/employees.csv
├── groups/          # modelo de grupos e ligação com as funções
├── policies/        # senha, bloqueio de conta, GPOs, Conditional Access
└── documentation/   # matriz de IAM, entrada/mudança/saída de funcionários, revisão de acessos
```
