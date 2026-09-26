# Project 04 — Identity and Access Management

RBAC and least privilege for Moretti Group, evolving from Active Directory to hybrid identity
and Entra ID ([ADR-006](../docs/adr/ADR-006-identity-evolution.md)).

**Status:** planned for Phase 5 (AD) and Phase 8 (Entra ID).

Planned layout:

```
project-04-iam/
├── users/           # provisioning from data/employees.csv
├── groups/          # group model and role mapping
├── policies/        # password, lockout, GPOs, Conditional Access
└── documentation/   # IAM matrix, Joiner/Mover/Leaver, access reviews
```
