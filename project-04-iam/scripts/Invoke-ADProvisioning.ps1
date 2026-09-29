<#
.SYNOPSIS
    Applies the generated Active Directory plan (project-04-iam/generated/ad-plan.json) to the
    domain.

.DESCRIPTION
    Run on DC01 after Install-DomainController.ps1. Every decision (which OUs, groups, accounts and
    memberships exist) is made by the plan, generated and tested from data/. This script only makes
    the domain match it, and can be run again at any time:

      - creates what is missing and updates what differs;
      - makes the membership of every group in the plan exactly as listed, which is how movers and
        leavers lose access;
      - only adds members to built-in groups (Domain Admins, Protected Users) and warns about
        anything else in them, so a mistake in the plan cannot lock the operator out.

    New account passwords are random, stored in SSM Parameter Store and never printed.
    Use -WhatIf to see every change without applying it.

.EXAMPLE
    .\Invoke-ADProvisioning.ps1 -WhatIf
    .\Invoke-ADProvisioning.ps1
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$PlanPath = (Join-Path $PSScriptRoot '..\generated\ad-plan.json'),
    [string]$Region = 'us-east-1',
    # Amazon-provided DNS, reachable from every instance; resolves names outside the domain.
    [string]$DnsForwarder = '169.254.169.253'
)

. (Join-Path $PSScriptRoot 'LabCommon.ps1')
Import-Module ActiveDirectory

$plan = Read-LabPlan -Path $PlanPath
$domain = Get-ADDomain
if ($domain.DNSRoot -ne $plan.domain.fqdn) {
    throw "The plan is for $($plan.domain.fqdn), but this is $($domain.DNSRoot)."
}

$summary = [ordered]@{ Created = 0; Updated = 0; Removed = 0 }
$passwordLength = @{ 'employee' = 16; 'admin' = 24; 'break-glass' = 32; 'service' = 32 }
# LDAP attribute -> plan field, for the plain text attributes of an account.
$userAttributes = [ordered]@{
    givenName   = 'given_name'
    sn          = 'surname'
    displayName = 'display_name'
    employeeID  = 'employee_id'
    department  = 'department'
    title       = 'title'
    description = 'description'
}
$schemaGuid = @{
    User               = [guid]'bf967aba-0de6-11d0-a285-00aa003049e2'
    Computer           = [guid]'bf967a86-0de6-11d0-a285-00aa003049e2'
    ResetPassword      = [guid]'00299570-246d-11d0-a768-00aa006e0529'
    PwdLastSet         = [guid]'bf967a0a-0de6-11d0-a285-00aa003049e2'
    LockoutTime        = [guid]'28630ebf-41d5-11d1-a9c1-0000f80367c1'
    UserAccountControl = [guid]'bf967a68-0de6-11d0-a285-00aa003049e2'
}

function Invoke-LabChange {
    # Runs a change unless -WhatIf, and counts it.
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Target, [string]$Action, [scriptblock]$Change, [string]$Kind = 'Updated')
    if ($PSCmdlet.ShouldProcess($Target, $Action)) {
        & $Change
        $summary[$Kind]++
    }
}

function Get-LabParentDn([string]$Dn) { ($Dn -split ',', 2)[1] }

function Test-LabDn([string]$Dn) {
    [bool](Get-ADObject -Filter "DistinguishedName -eq '$Dn'")
}

# ---------------------------------------------------------------------------- domain settings
$forwarders = @(Get-DnsServerForwarder | ForEach-Object { $_.IPAddress } | ForEach-Object { "$_" })
if ($forwarders -notcontains $DnsForwarder) {
    Invoke-LabChange -Target 'DNS server' -Action "Forward external names to $DnsForwarder" -Change {
        Set-DnsServerForwarder -IPAddress $DnsForwarder
    }
}

$quota = (Get-ADObject -Identity $domain.DistinguishedName -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'
if ($quota -ne [int]$plan.machine_account_quota) {
    Invoke-LabChange -Target $domain.DNSRoot -Action "Set the machine account quota to $($plan.machine_account_quota)" -Change {
        Set-ADDomain -Identity $domain -Replace @{ 'ms-DS-MachineAccountQuota' = [int]$plan.machine_account_quota }
    }
}

$policy = $plan.default_password_policy
$current = Get-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot
if ($current.MinPasswordLength -ne $policy.min_length -or $current.LockoutThreshold -ne $policy.lockout_threshold -or
    $current.PasswordHistoryCount -ne $policy.history -or $current.MaxPasswordAge.Days -ne $policy.max_age_days) {
    Invoke-LabChange -Target $domain.DNSRoot -Action 'Apply the default password and lockout policy' -Change {
        Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot `
            -MinPasswordLength $policy.min_length `
            -ComplexityEnabled $policy.complexity `
            -PasswordHistoryCount $policy.history `
            -MinPasswordAge (New-TimeSpan -Days $policy.min_age_days) `
            -MaxPasswordAge (New-TimeSpan -Days $policy.max_age_days) `
            -LockoutThreshold $policy.lockout_threshold `
            -LockoutDuration (New-TimeSpan -Minutes $policy.lockout_duration_minutes) `
            -LockoutObservationWindow (New-TimeSpan -Minutes $policy.lockout_window_minutes) `
            -ReversibleEncryptionEnabled $false
    }
}

# ---------------------------------------------------------------------------- OUs
foreach ($dn in $plan.organizational_units) {
    if (-not (Test-LabDn $dn)) {
        $name = ($dn -split ',', 2)[0] -replace '^OU=', ''
        Invoke-LabChange -Target $dn -Action 'Create OU' -Change {
            New-ADOrganizationalUnit -Name $name -Path (Get-LabParentDn $dn) -ProtectedFromAccidentalDeletion $true
        } -Kind 'Created'
    }
}

# ---------------------------------------------------------------------------- groups
foreach ($group in $plan.groups) {
    $existing = Get-ADGroup -Filter "SamAccountName -eq '$($group.name)'" -Properties Description
    if (-not $existing) {
        Invoke-LabChange -Target $group.name -Action 'Create group' -Change {
            New-ADGroup -Name $group.name -SamAccountName $group.name -GroupScope $group.scope `
                -GroupCategory Security -Path $group.ou -Description $group.description
        } -Kind 'Created'
        continue
    }
    if ($existing.Description -ne $group.description) {
        Invoke-LabChange -Target $group.name -Action 'Update description' -Change { Set-ADGroup -Identity $existing -Description $group.description }
    }
    if ((Get-LabParentDn $existing.DistinguishedName) -ne $group.ou) {
        Invoke-LabChange -Target $group.name -Action "Move to $($group.ou)" -Change { Move-ADObject -Identity $existing -TargetPath $group.ou }
    }
}

# ---------------------------------------------------------------------------- accounts
$properties = @($userAttributes.Keys) + @('company', 'Enabled', 'AccountExpirationDate', 'PasswordNeverExpires', 'Manager')
foreach ($user in $plan.users) {
    $filter = "SamAccountName -eq '$($user.sam)'"
    if (-not (Get-ADUser -Filter $filter)) {
        # Created disabled; the checks below enable it when the plan says so.
        $password = Get-LabOrNewSecret -Name $user.password_parameter -Region $Region -Length $passwordLength[$user.kind]
        Invoke-LabChange -Target $user.sam -Action 'Create account' -Change {
            New-ADUser -Name $user.sam -SamAccountName $user.sam -UserPrincipalName $user.upn -Path $user.ou `
                -AccountPassword (ConvertTo-LabSecureString -Value $password) -Enabled $false `
                -ChangePasswordAtLogon $user.must_change_password -PasswordNeverExpires $user.password_never_expires
        } -Kind 'Created'
    }
    $existing = Get-ADUser -Filter $filter -Properties $properties
    if (-not $existing) { continue }  # -WhatIf: the account was not created

    if ((Get-LabParentDn $existing.DistinguishedName) -ne $user.ou) {
        Invoke-LabChange -Target $user.sam -Action "Move to $($user.ou)" -Change { Move-ADObject -Identity $existing -TargetPath $user.ou }
    }

    $desired = @{ company = 'Moretti Group' }
    foreach ($attribute in $userAttributes.Keys) { $desired[$attribute] = $user.($userAttributes[$attribute]) }
    foreach ($attribute in $desired.Keys) {
        $want = [string]$desired[$attribute]
        $have = [string]$existing.$attribute
        if ($want -ceq $have) { continue }
        if ($want) {
            Invoke-LabChange -Target $user.sam -Action "Set $attribute" -Change { Set-ADUser -Identity $existing -Replace @{ $attribute = $want } }
        }
        else {
            Invoke-LabChange -Target $user.sam -Action "Clear $attribute" -Change { Set-ADUser -Identity $existing -Clear $attribute }
        }
    }

    if ($existing.Enabled -ne [bool]$user.enabled) {
        if ($user.enabled) {
            Invoke-LabChange -Target $user.sam -Action 'Enable account' -Change { Enable-ADAccount -Identity $existing }
        }
        else {
            Invoke-LabChange -Target $user.sam -Action 'Disable account' -Change { Disable-ADAccount -Identity $existing }
        }
    }

    # expires_after is the last valid day: the account expires at the start of the next one.
    $expires = $null
    if ($user.expires_after) {
        $expires = [datetime]::ParseExact($user.expires_after, 'yyyy-MM-dd', $null).AddDays(1)
    }
    if ($expires -and $existing.AccountExpirationDate -ne $expires) {
        Invoke-LabChange -Target $user.sam -Action "Expire after $($user.expires_after)" -Change { Set-ADAccountExpiration -Identity $existing -DateTime $expires }
    }
    elseif (-not $expires -and $existing.AccountExpirationDate) {
        Invoke-LabChange -Target $user.sam -Action 'Remove expiration date' -Change { Clear-ADAccountExpiration -Identity $existing }
    }

    if ($existing.PasswordNeverExpires -ne [bool]$user.password_never_expires) {
        Invoke-LabChange -Target $user.sam -Action 'Set password expiry' -Change {
            Set-ADUser -Identity $existing -PasswordNeverExpires $user.password_never_expires
        }
    }
}

# Managers last: every account exists by now.
foreach ($user in @($plan.users | Where-Object { $_.manager })) {
    $account = Get-ADUser -Filter "SamAccountName -eq '$($user.sam)'" -Properties Manager
    $manager = Get-ADUser -Filter "SamAccountName -eq '$($user.manager)'"
    if ($account -and $manager -and $account.Manager -ne $manager.DistinguishedName) {
        Invoke-LabChange -Target $user.sam -Action "Set manager $($user.manager)" -Change { Set-ADUser -Identity $account -Manager $manager }
    }
}

# ---------------------------------------------------------------------------- managed service accounts
if (@($plan.managed_service_accounts).Count -gt 0 -and -not (Get-KdsRootKey)) {
    # Lab shortcut: a root key dated 10 hours back is usable at once instead of after 10 hours.
    Invoke-LabChange -Target 'KDS' -Action 'Create the KDS root key for gMSAs' -Change {
        Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) | Out-Null
    } -Kind 'Created'
}
$serviceOu = @($plan.organizational_units | Where-Object { $_ -like 'OU=ServiceAccounts,*' })[0]
foreach ($gmsa in $plan.managed_service_accounts) {
    if (-not (Get-ADServiceAccount -Filter "Name -eq '$($gmsa.name)'")) {
        Invoke-LabChange -Target $gmsa.name -Action 'Create group managed service account' -Change {
            New-ADServiceAccount -Name $gmsa.name -DNSHostName "$($gmsa.name).$($plan.domain.fqdn)" `
                -Path $serviceOu -Description $gmsa.description
        } -Kind 'Created'
    }
}

# ---------------------------------------------------------------------------- memberships
foreach ($group in $plan.groups) {
    if (-not (Get-ADGroup -Filter "SamAccountName -eq '$($group.name)'")) { continue }  # -WhatIf
    $current = @(Get-ADGroupMember -Identity $group.name | ForEach-Object { $_.SamAccountName })
    $wanted = @($group.members)
    $add = @($wanted | Where-Object { $current -notcontains $_ })
    $remove = @($current | Where-Object { $wanted -notcontains $_ })
    if ($add.Count -gt 0) {
        Invoke-LabChange -Target $group.name -Action "Add $($add -join ', ')" -Change { Add-ADGroupMember -Identity $group.name -Members $add }
    }
    if ($remove.Count -gt 0) {
        Invoke-LabChange -Target $group.name -Action "Remove $($remove -join ', ')" -Change {
            Remove-ADGroupMember -Identity $group.name -Members $remove -Confirm:$false
        } -Kind 'Removed'
    }
}

foreach ($entry in $plan.builtin_group_members.PSObject.Properties) {
    $current = @(Get-ADGroupMember -Identity $entry.Name | ForEach-Object { $_.SamAccountName })
    $wanted = @($entry.Value)
    $add = @($wanted | Where-Object { $current -notcontains $_ -and (Get-ADObject -Filter "SamAccountName -eq '$_'") })
    if ($add.Count -gt 0) {
        Invoke-LabChange -Target $entry.Name -Action "Add $($add -join ', ')" -Change { Add-ADGroupMember -Identity $entry.Name -Members $add }
    }
    $extra = @($current | Where-Object { $wanted -notcontains $_ })
    if ($extra.Count -gt 0) {
        Write-Warning "$($entry.Name) also contains: $($extra -join ', '). Review them (operator checklist, phase 5)."
    }
}

# ---------------------------------------------------------------------------- fine-grained password policies
foreach ($pso in $plan.fine_grained_password_policies) {
    $settings = @{
        Precedence                  = $pso.precedence
        MinPasswordLength           = $pso.min_length
        ComplexityEnabled           = $pso.complexity
        PasswordHistoryCount        = $pso.history
        MinPasswordAge              = New-TimeSpan -Days $pso.min_age_days
        MaxPasswordAge              = New-TimeSpan -Days $pso.max_age_days
        LockoutThreshold            = $pso.lockout_threshold
        LockoutDuration             = New-TimeSpan -Minutes $pso.lockout_duration_minutes
        LockoutObservationWindow    = New-TimeSpan -Minutes $pso.lockout_window_minutes
        ReversibleEncryptionEnabled = $false
    }
    if (-not (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$($pso.name)'")) {
        Invoke-LabChange -Target $pso.name -Action 'Create fine-grained password policy' -Change {
            New-ADFineGrainedPasswordPolicy -Name $pso.name @settings
        } -Kind 'Created'
    }
    else {
        Invoke-LabChange -Target $pso.name -Action 'Apply fine-grained password policy settings' -Change {
            Set-ADFineGrainedPasswordPolicy -Identity $pso.name @settings
        }
    }
    if (-not (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$($pso.name)'")) { continue }  # -WhatIf
    $subjects = @(Get-ADFineGrainedPasswordPolicySubject -Identity $pso.name | ForEach-Object { $_.Name })
    foreach ($subject in @($pso.applies_to | Where-Object { $subjects -notcontains $_ })) {
        Invoke-LabChange -Target $pso.name -Action "Apply to $subject" -Change {
            Add-ADFineGrainedPasswordPolicySubject -Identity $pso.name -Subjects $subject
        }
    }
}

# ---------------------------------------------------------------------------- delegations
function Get-LabDelegationRule {
    # Access rules that implement one delegated right for a group SID.
    param([string]$Right, [System.Security.Principal.SecurityIdentifier]$Sid)
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $readWrite = [System.DirectoryServices.ActiveDirectoryRights]'ReadProperty, WriteProperty'
    $extended = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
    $onUsers = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
    $thisObject = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
    switch ($Right) {
        'reset-password' {
            New-Object System.DirectoryServices.ActiveDirectoryAccessRule($Sid, $extended, $allow, $schemaGuid.ResetPassword, $onUsers, $schemaGuid.User)
            New-Object System.DirectoryServices.ActiveDirectoryAccessRule($Sid, $readWrite, $allow, $schemaGuid.PwdLastSet, $onUsers, $schemaGuid.User)
            New-Object System.DirectoryServices.ActiveDirectoryAccessRule($Sid, $readWrite, $allow, $schemaGuid.LockoutTime, $onUsers, $schemaGuid.User)
        }
        'disable-account' {
            New-Object System.DirectoryServices.ActiveDirectoryAccessRule($Sid, $readWrite, $allow, $schemaGuid.UserAccountControl, $onUsers, $schemaGuid.User)
        }
        'join-computers' {
            $rights = [System.DirectoryServices.ActiveDirectoryRights]'CreateChild, DeleteChild'
            New-Object System.DirectoryServices.ActiveDirectoryAccessRule($Sid, $rights, $allow, $schemaGuid.Computer, $thisObject, [guid]::Empty)
        }
        default { throw "Unknown delegated right '$Right'." }
    }
}

foreach ($delegation in $plan.delegations) {
    $group = Get-ADGroup -Filter "SamAccountName -eq '$($delegation.group)'"
    if (-not $group -or -not (Test-LabDn $delegation.ou)) { continue }  # -WhatIf
    $path = "AD:\$($delegation.ou)"
    $acl = Get-Acl -Path $path
    $present = @($acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
    $missing = @(Get-LabDelegationRule -Right $delegation.right -Sid $group.SID | Where-Object {
            $rule = $_
            -not ($present | Where-Object {
                    $_.IdentityReference -eq $rule.IdentityReference -and $_.ObjectType -eq $rule.ObjectType -and
                    $_.InheritedObjectType -eq $rule.InheritedObjectType -and
                    ($_.ActiveDirectoryRights -band $rule.ActiveDirectoryRights) -eq $rule.ActiveDirectoryRights
                })
        })
    if ($missing.Count -gt 0) {
        Invoke-LabChange -Target $delegation.ou -Action "Delegate $($delegation.right) to $($delegation.group)" -Change {
            foreach ($rule in $missing) { $acl.AddAccessRule($rule) }
            Set-Acl -Path $path -AclObject $acl
        }
    }
}

Write-Output ("Done. Created: {0}  Updated: {1}  Removed from groups: {2}" -f $summary.Created, $summary.Updated, $summary.Removed)
