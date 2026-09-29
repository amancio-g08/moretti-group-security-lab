# Active Directory Validation Plan

Tests to run after the phase 5 steps of the [operator checklist](../../docs/operator-checklist.md).
Each test names the design rule it proves ([AD design](ad-design.md)).

> **Status: not executed.** The "Result" column is filled in only with what is actually observed on
> DC01 and WS-FIN01. The offline tests (Python plan tests, PowerShell dry runs, PSScriptAnalyzer)
> check the code, not the running domain, and are not a substitute for these tests.

All commands run in PowerShell on DC01 (SSM session) unless stated otherwise.
`$base = 'OU=Moretti,DC=corp,DC=moretti,DC=internal'`.

| ID | Rule | How | Expected | Result |
|---|---|---|---|---|
| AD-01 | Forest | `Get-ADDomain \| Select DNSRoot, NetBIOSName` | `corp.moretti.internal`, `CORP` | Not executed |
| AD-02 | Idempotent provisioning | Run `Invoke-ADProvisioning.ps1` a second time | `Created: 0  Updated: 0  Removed from groups: 0` | Not executed |
| AD-03 | Accounts from data/ | `(Get-ADUser -SearchBase $base -Filter *).Count` | 86 (73 employees, 9 admin, 3 service, 1 break-glass) | Not executed |
| AD-04 | Leaver | `Get-ADUser alan.moreira -Properties MemberOf \| Select Enabled, DistinguishedName, MemberOf` | Disabled, in `OU=Disabled`, no groups | Not executed |
| AD-05 | On leave | `(Get-ADUser aline.barros).Enabled` | `False` | Not executed |
| AD-06 | Contract end | `(Get-ADUser leandro.viana -Properties AccountExpirationDate).AccountExpirationDate` | 2026-10-31 00:00 (end of 2026-10-30) | Not executed |
| AD-07 | Tier 0 | `Get-ADGroupMember 'Domain Admins' -Recursive \| Select SamAccountName` | `adm-marcio.guimaraes`, `bg-admin01`, plus the built-in `Administrator` until the checklist removes it; record anything else (e.g. `ssm-user`) | Not executed |
| AD-08 | Admin password policy | `Get-ADUserResultantPasswordPolicy adm-ana.costa` | `PSO-Admin-Accounts` | Not executed |
| AD-09 | Machine account quota | `(Get-ADDomain \| Get-ADObject -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'` | `0` | Not executed |
| AD-10 | Delegation | `(Get-Acl "AD:\OU=Users,$base").Access \| Where IdentityReference -match 'UserPasswordReset\|UserDisable' \| Select IdentityReference, ActiveDirectoryRights, ObjectType` | Reset-password extended right and property writes for the two DL groups | Not executed |
| AD-11 | Domain join (Tier 2) | `Get-ADComputer WS-FIN01 \| Select DistinguishedName` | In `OU=Workstations,OU=Computers,...` | Not executed |
| AD-12 | GPOs applied | On WS-FIN01: `gpresult /r /scope computer` | `MG-Baseline-Security`, `MG-Member-Computers`, `MG-Workstation-Admins` listed as applied | Not executed |
| AD-13 | Hardening | On WS-FIN01: `(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient').EnableMulticast` | `0` | Not executed |
| AD-14 | Audit policy | On WS-FIN01: `auditpol /get /subcategory:Logon` | `Success and Failure` | Not executed |
| AD-15 | Audit events | On WS-FIN01: `net use \\DC01\NETLOGON /user:CORP\joao.silva DeliberatelyWrong1!`; then on DC01: `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625,4771,4776} -MaxEvents 5` | A failure event naming `joao.silva` | Not executed |
| AD-16 | End to end with P05 | Export 4624/4625 from DC01 (P05 README), then `moretti-sec analyze logons.json` on the Mac | Report generated; findings depend on the activity, recorded as observed | Not executed |

Record evidence in `project-04-iam/documentation/evidence/` using the test ID as the file name.
Never include passwords, account IDs or SIDs of the real AWS account in committed evidence.
