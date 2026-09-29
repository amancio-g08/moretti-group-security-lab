# Dry runs of Invoke-ADProvisioning.ps1 against a simulated domain (SYNTHETIC: no Active
# Directory, no AWS). Stubs replace the ActiveDirectory, DnsServer and AWS cmdlets, and the script
# runs with -WhatIf, so every change is only announced; any stub that would change state throws.
# This catches runtime errors (misspelled properties, scoping, strict mode) and checks the leaver
# logic. It does not prove that the changes work against a real domain controller.
#
#   pwsh -NoProfile -File project-04-iam/tests/Test-ProvisioningDryRun.ps1
#
# Scenarios (each runs in its own process, because -WhatIf messages go straight to the console):
#   empty   nothing exists yet: every object is created
#   leaver  MG-0097 (terminated in data/) is still enabled, in its department OU and groups
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '',
    Justification = 'The stubs replace cmdlets globally and read the simulated directory from there.')]
param([ValidateSet('empty', 'leaver')][string]$Scenario)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$domainDn = 'DC=corp,DC=moretti,DC=internal'

if (-not $Scenario) {
    $pwsh = (Get-Process -Id $PID).Path
    $expected = @{
        empty  = @('"Create account" on target "joao.silva"', '"Create group" on target "GG-Role-FinanceStaff"',
                   '"Create group managed service account" on target "svc-backup"')
        leaver = @("`"Move to OU=Disabled,OU=Moretti,$domainDn`" on target `"alan.moreira`"",
                   '"Disable account" on target "alan.moreira"',
                   '"Set description" on target "alan.moreira"',
                   '"Remove alan.moreira" on target "GG-Role-Support"',
                   '"Remove alan.moreira" on target "GG-All-Staff"')
    }
    $unexpected = @{ empty = @(); leaver = @('on target "/moretti-group-lab/ad/users/alan.moreira"') }
    $failed = $false
    foreach ($name in 'empty', 'leaver') {
        $text = (& $pwsh -NoProfile -File $PSCommandPath -Scenario $name 2>&1) -join "`n"
        $problems = @($expected[$name] | Where-Object { -not $text.Contains($_) } | ForEach-Object { "missing: $_" })
        $problems += @($unexpected[$name] | Where-Object { $text.Contains($_) } | ForEach-Object { "unexpected: $_" })
        if ($text -notmatch 'Done\. Created') { $problems += 'the script did not finish' }
        if ($problems) {
            $failed = $true
            Write-Output "FAIL $name`n  $($problems -join "`n  ")`n$text"
        }
        else {
            Write-Output "PASS $name"
        }
    }
    if ($failed) { exit 1 }
    exit 0
}

# ---------------------------------------------------------------------------- simulated directory
$users = @{}
$groups = @{}
if ($Scenario -eq 'leaver') {
    $users['alan.moreira'] = [pscustomobject]@{
        SamAccountName = 'alan.moreira'
        DistinguishedName = "CN=alan.moreira,OU=IT Support,OU=Users,OU=Moretti,$domainDn"
        Enabled = $true; givenName = 'Alan'; sn = 'Moreira'; displayName = 'Alan Moreira'
        employeeID = 'MG-0097'; department = 'IT Support'; title = 'Service Desk Analyst'
        description = ''; company = 'Moretti Group'; AccountExpirationDate = $null
        PasswordNeverExpires = $false; Manager = $null
    }
    foreach ($group in 'GG-Role-Support', 'GG-All-Staff') {
        $groups[$group] = [pscustomobject]@{
            SamAccountName = $group; Description = ''; Members = @('alan.moreira')
            DistinguishedName = "CN=$group,OU=Roles,OU=Groups,OU=Moretti,$domainDn"
        }
    }
}
$global:SimUsers = $users
$global:SimGroups = $groups

function global:Get-SimName([object[]]$Arguments) {
    $text = "$Arguments"
    if ($text -match "SamAccountName -eq '([^']+)'") { return $Matches[1] }
    $index = [array]::IndexOf($Arguments, '-Identity')
    if ($index -ge 0) { return "$($Arguments[$index + 1])" }
    $null
}

function global:Import-Module { }  # ActiveDirectory and AWSPowerShell do not exist here
function global:Get-ADDomain { [pscustomobject]@{ DNSRoot = 'corp.moretti.internal'; DistinguishedName = 'DC=corp,DC=moretti,DC=internal' } }
function global:Get-DnsServerForwarder { [pscustomobject]@{ IPAddress = @() } }
function global:Get-ADObject {
    if ("$args" -match '-Identity') { return [pscustomobject]@{ 'ms-DS-MachineAccountQuota' = 10 } }
    $null  # no OU exists yet
}
function global:Get-ADDefaultDomainPasswordPolicy {
    [pscustomobject]@{ MinPasswordLength = 7; LockoutThreshold = 0; PasswordHistoryCount = 24; MaxPasswordAge = New-TimeSpan -Days 42 }
}
function global:Get-ADUser { $global:SimUsers[(Get-SimName $args)] }
function global:Get-ADGroup { $global:SimGroups[(Get-SimName $args)] }
function global:Get-ADGroupMember {
    $group = $global:SimGroups[(Get-SimName $args)]
    if ($group) { $group.Members | ForEach-Object { [pscustomobject]@{ SamAccountName = $_ } } }
}
foreach ($name in 'Get-ADServiceAccount', 'Get-ADFineGrainedPasswordPolicy', 'Get-KdsRootKey') {
    Set-Item -Path "function:global:$name" -Value { $null }
}
function global:Get-SSMParameter { throw 'ParameterNotFound: (simulated) parameter does not exist' }
function global:Write-SSMParameter { throw 'Write-SSMParameter must not run under -WhatIf' }

$stateChanging = @(
    'Set-DnsServerForwarder', 'Set-ADDomain', 'Set-ADDefaultDomainPasswordPolicy', 'New-ADOrganizationalUnit',
    'New-ADGroup', 'Set-ADGroup', 'Move-ADObject', 'New-ADUser', 'Set-ADUser', 'Enable-ADAccount',
    'Disable-ADAccount', 'Set-ADAccountExpiration', 'Clear-ADAccountExpiration', 'Add-KdsRootKey',
    'New-ADServiceAccount', 'Add-ADGroupMember', 'Remove-ADGroupMember', 'New-ADFineGrainedPasswordPolicy',
    'Set-ADFineGrainedPasswordPolicy', 'Add-ADFineGrainedPasswordPolicySubject', 'Set-Acl'
)
foreach ($name in $stateChanging) {
    Set-Item -Path "function:global:$name" -Value ([scriptblock]::Create("throw '$name ran under -WhatIf'"))
}

& (Join-Path $root 'scripts/Invoke-ADProvisioning.ps1') -PlanPath (Join-Path $root 'generated/ad-plan.json') -WhatIf
