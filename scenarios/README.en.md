# scenarios/ — End-to-end lab scenarios

[Português](README.md) | **English**

Each scenario (`SCN-xx`) is traced across every relevant evidence source: network captures,
VPC Flow Logs, Wazuh alerts, Python reports, IAM actions and the incident report. The scenario ID
is reused in filenames and references so that one event can be followed through the whole lab.

**Status:** planned for Phase 7.

| ID | Scenario (draft) |
|---|---|
| SCN-01 | Password-guessing attempts from GUEST01 against lab hosts |
| SCN-02 | Authentication attempt with a terminated employee account |
| SCN-03 | Unexpected addition to a privileged group |
| SCN-04 | Segmentation violation: GUEST → FINANCE |
| SCN-05 | Unauthorized configuration change on the finance application |
| FP-01 | Authorized activity that triggers an alert and becomes a documented exception |

Offensive activity follows [docs/lab-safety.md](../docs/lab-safety.md).
