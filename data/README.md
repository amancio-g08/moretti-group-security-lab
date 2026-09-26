# data/ — Source of truth

Machine-readable policy and company data consumed by every project ([ADR-001](../docs/adr/ADR-001-source-of-truth.md)).

**Status:** planned for Phase 1.

| Planned file | Content | Consumers |
|---|---|---|
| `network-matrix.yaml` | Allowed/denied flows between segments, with justification and `applies_to` | P01 ACLs, Terraform Security Groups, P05 validation |
| `departments.yaml` | Departments, segments, data owners | P04, P05 |
| `employees.csv` | Fictitious employees, department, role | P04 AD provisioning, P05 enrichment, Wazuh CDB lists |
| `assets.yaml` | Hosts, segment, IP, owner, criticality, classification | P05 enrichment, threat model |
| `iam-roles.yaml` | Roles and entitlements | P04 RBAC, access reviews |

All data here is fictitious.
