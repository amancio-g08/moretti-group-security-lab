# Checks the Group Policy files built by scripts/GpoTemplates.ps1 (SYNTHETIC SIDs; no domain).
#
#   pwsh -NoProfile -File project-04-iam/tests/Test-GpoTemplates.ps1

$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/GpoTemplates.ps1')

$failures = New-Object System.Collections.Generic.List[string]
function Assert-Lab([bool]$Condition, [string]$Message) { if (-not $Condition) { $failures.Add($Message) } }

$domainSid = 'S-1-5-21-1111111111-2222222222-3333333333'
$template = ConvertTo-LabSecurityTemplate `
    -PrivilegeRights @{
        SeDenyRemoteInteractiveLogonRight = @("$domainSid-1105", "$domainSid-512")
        SeDenyInteractiveLogonRight       = @("$domainSid-1105", "$domainSid-512")
    } `
    -LocalGroupMembers @{ "$domainSid-1107" = @('S-1-5-32-544') }

Assert-Lab ($template[3] -ceq 'signature="$CHICAGO$"') 'signature line must be literal'
Assert-Lab ($template -contains '[Privilege Rights]') 'privilege rights section'
Assert-Lab ($template -contains "SeDenyInteractiveLogonRight = *$domainSid-1105,*$domainSid-512") 'deny interactive logon SIDs'
Assert-Lab ([array]::IndexOf($template, "SeDenyInteractiveLogonRight = *$domainSid-1105,*$domainSid-512") -lt
    [array]::IndexOf($template, "SeDenyRemoteInteractiveLogonRight = *$domainSid-1105,*$domainSid-512")) 'rights are sorted'
Assert-Lab ($template -contains "*$domainSid-1107__Memberof = *S-1-5-32-544") 'domain group added to local Administrators'
Assert-Lab ($template -contains "*$domainSid-1107__Members =") 'Members left empty (additive membership)'

$empty = ConvertTo-LabSecurityTemplate
Assert-Lab (-not ($empty -contains '[Privilege Rights]') -and -not ($empty -contains '[Group Membership]')) 'no empty sections'

$audit = ConvertTo-LabAuditCsv -Subcategories $LabAuditSubcategories
Assert-Lab ($audit[0] -ceq 'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value') 'audit.csv header'
Assert-Lab ($audit -contains ',System,Audit Logon,{0cce9215-69ae-11d9-bed3-505054503030},Success and Failure,,3') 'logon success and failure (4624, 4625)'
Assert-Lab ($audit -contains ',System,Audit Account Lockout,{0cce9217-69ae-11d9-bed3-505054503030},Failure,,2') 'account lockout failure'
Assert-Lab ($audit.Count -eq $LabAuditSubcategories.Count + 1) 'one line per subcategory'
Assert-Lab (@($LabAuditSubcategories | ForEach-Object { $_.Guid } | Sort-Object -Unique).Count -eq $LabAuditSubcategories.Count) 'unique subcategory GUIDs'

$registry = '[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]'
$merged = Merge-LabExtensionName -Current $registry -Add $LabCseSecurity, $LabCseAudit
Assert-Lab ($merged -ceq ($registry + $LabCseSecurity + $LabCseAudit)) "extensions sorted by GUID: $merged"
Assert-Lab ((Merge-LabExtensionName -Current $merged -Add $LabCseAudit) -ceq $merged) 'merge is idempotent'
Assert-Lab ((Merge-LabExtensionName -Current '' -Add $LabCseAudit) -ceq $LabCseAudit) 'empty current value'

if ($failures.Count -gt 0) {
    Write-Output "FAIL`n  $($failures -join "`n  ")"
    exit 1
}
Write-Output 'PASS gpo templates'
