# Triage Playbooks

What to do when a custom rule fires ([rule catalog](soc-design.md#4-rule-catalog)). Each playbook
answers the same questions: is it real, how bad is it, what to contain, and what to record.
Containment actions use the delegated rights of phase 5: the SOC role can disable standard user
accounts (`DL-AD-UserDisable`), nothing more.

Every alert handled is written up in `project-03-soc/alerts/` as true or false positive, with the
evidence that decided it. Incidents get a report in `project-03-soc/incidents/`.

## ACC-01 — Terminated employee's account

1. **Confirm:** `Get-ADUser <account> -Properties Enabled, DistinguishedName, whenChanged`. The
   account should be disabled and in `OU=Disabled`. A successful logon (100100) means it is not,
   or that the event predates the change.
2. **Scope:** source address (`win.eventdata.ipAddress`) → asset and segment with
   `moretti-sec analyze`; other logons of the same account in the last 14 days.
3. **Contain:** disable the account if it is enabled; if the source is a workstation, treat that
   workstation as suspect.
4. **Record:** why the account was usable (a provisioning run missed, a manual re-enable), and fix
   the cause.

## ACC-02 — Employee on leave

1. **Confirm with the manager** (from `employees.csv`) whether the employee is really working.
2. A success means the account was re-enabled: check who did it (event 4722 on DC01).
3. If nobody authorized it, disable the account and handle it as ACC-01.

## ACC-03 — Expired account

1. Usually a contractor still trying to work after the contract: confirm the `end_date` in
   `employees.csv`.
2. Repeated attempts from an unexpected address: handle as a brute force (BF-01).
3. **Record** whether the contract was extended; if it was, the fix is in `data/`, not in AD.

## ACC-04 — Break-glass account

1. **Every use is an incident** by policy (`accounts.yaml`). Open an incident record first.
2. Contact the security team: was an emergency declared?
3. If yes: log what was done with the account, then rotate its password (new value in SSM).
4. If no: treat it as a compromise of the highest privilege. Keep the evidence (Security log of
   DC01, the source host) before any change.

## ACC-05 — Service account at a keyboard

1. Service accounts are denied interactive and RDP logon by GPO on member computers, so a success
   points to a host outside that GPO (for example a domain controller) or to a changed GPO.
2. Identify the source address and the person behind it; the service's own logons are network
   logons (type 3) and do not trigger this rule.
3. Rotate the service account's password and check the host for the credentials that were used.

## ACC-06 — Logon type not granted

1. This is the tiering control **working**: a Domain Admin or a service account was stopped from
   logging on to a member computer.
2. Find out why someone tried: a mistake (an admin using the wrong account) or credential
   misuse. Talk to the account owner.
3. Repeated attempts with several accounts from one source: treat as lateral movement.

## BF-01 — Brute force from the guest network

1. The guest network must not reach internal hosts at all (NM-004). A brute force against an
   internal host from there means **both** an attack and a segmentation gap: check the
   Security Groups and the NET-01 alerts at the same time.
2. Identify the guest host; in the lab it is GUEST01, the simulated attacker (in-scope scenarios
   only, lab safety).
3. Check for any successful logon from the same address afterwards (`moretti-sec` BF-02).

## NET-01 — Guest traffic rejected

1. The control worked (the Security Group rejected the traffic); the alert is about the intent.
2. List the destinations and ports tried: a sweep across many hosts or ports is reconnaissance
   (T1046).
3. Correlate with the capture on GUEST01 and on the target (SCN-04 run book, phase 7).

## CT-01 — Security Group changed

1. Changes are expected only from `terraform apply` by the operator's Identity Center role. Check
   `userIdentity.arn` and the time against the operator's session.
2. Any change made outside Terraform: compare the group with `terraform plan`, revert it and find
   out who made it and why.

## CT-02 — Root user activity

1. The root user is kept for account-level tasks only (lab safety). Confirm with the owner.
2. Unexpected use: change the root password, check MFA, review everything done in that session.

## CT-03 — Audit logging changed

1. Stopping CloudTrail or deleting Flow Logs blinds the SOC: treat it as an incident until proven
   otherwise.
2. Re-enable logging (`terraform apply` restores it), then review CloudTrail for what happened
   right before and after.
