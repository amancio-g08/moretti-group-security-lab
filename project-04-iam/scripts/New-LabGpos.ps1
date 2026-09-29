<#
.SYNOPSIS
    Creates, configures and links the lab Group Policy Objects.

.DESCRIPTION
    Run on DC01 after Invoke-ADProvisioning.ps1. Safe to run again: missing GPOs, settings and
    links are added, and a GPO file is rewritten (with a new GPO version) only when it differs.

      MG-Baseline-Security   domain root   protocol and credential hardening, advanced audit policy
      MG-Member-Computers    Workstations  host firewall, screen lock, no interactive logon for
                             and Servers   service accounts and Tier 0 (Domain Admins)
      MG-Workstation-Admins  Workstations  DL-Workstations-LocalAdmin joins local Administrators
      MG-Server-Admins       Servers       DL-Servers-LocalAdmin joins local Administrators

    Group names and target OUs come from the generated plan (data/). The security template and the
    audit policy are written as files in SYSVOL (GpoTemplates.ps1), because no cmdlet sets them.

.EXAMPLE
    .\New-LabGpos.ps1 -WhatIf
    .\New-LabGpos.ps1
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$PlanPath = (Join-Path $PSScriptRoot '..\generated\ad-plan.json')
)

. (Join-Path $PSScriptRoot 'LabCommon.ps1')
. (Join-Path $PSScriptRoot 'GpoTemplates.ps1')
Import-Module GroupPolicy
Import-Module ActiveDirectory

$plan = Read-LabPlan -Path $PlanPath
$lsa = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
$administrators = 'S-1-5-32-544'  # BUILTIN\Administrators on every computer

function Get-LabSid([string]$GroupName) { (Get-ADGroup -Identity $GroupName).SID.Value }

$gpos = @(
    @{
        Name     = 'MG-Baseline-Security'
        Comment  = 'Credential and protocol hardening for every computer, and the advanced audit policy.'
        Links    = @($plan.domain.dn)
        Registry = @(
            @{ Key = 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient'; Name = 'EnableMulticast'; Value = 0 }  # LLMNR off: no name poisoning
            @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'SMB1'; Value = 0 }  # SMBv1 server off
            @{ Key = $lsa; Name = 'LmCompatibilityLevel'; Value = 5 }  # NTLMv2 only; refuse LM and NTLMv1
            @{ Key = $lsa; Name = 'RunAsPPL'; Value = 1 }  # LSA protection against credential dumping
            @{ Key = $lsa; Name = 'SCENoApplyLegacyAuditPolicy'; Value = 1 }  # advanced audit subcategories win
            @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; Name = 'UseLogonCredential'; Value = 0 }  # no clear-text credentials in memory
            @{ Key = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name = 'ProcessCreationIncludeCmdLine_Enabled'; Value = 1 }  # command line in event 4688
            @{ Key = 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name = 'EnableScriptBlockLogging'; Value = 1 }  # event 4104
        )
        Audit    = $LabAuditSubcategories
    }
    @{
        Name            = 'MG-Member-Computers'
        Comment         = 'Host firewall, screen lock and logon restrictions on member computers.'
        Links           = @($plan.computer_ous.workstations, $plan.computer_ous.servers)
        Registry        = @(
            @{ Key = 'HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'; Name = 'EnableFirewall'; Value = 1 }
            @{ Key = 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name = 'EnableFirewall'; Value = 1 }
            @{ Key = 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name = 'EnableFirewall'; Value = 1 }
            @{ Key = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'InactivityTimeoutSecs'; Value = 900 }  # lock after 15 minutes
        )
        PrivilegeRights = @{
            SeDenyInteractiveLogonRight       = @($plan.deny_interactive_logon)
            SeDenyRemoteInteractiveLogonRight = @($plan.deny_interactive_logon)
        }
    }
    @{
        Name         = 'MG-Workstation-Admins'
        Comment      = 'Endpoint administrators (Tier 2) are local administrators of workstations.'
        Links        = @($plan.computer_ous.workstations)
        LocalAdmins  = @($plan.local_admin_groups.workstations)
    }
    @{
        Name         = 'MG-Server-Admins'
        Comment      = 'Server administrators (Tier 1) are local administrators of member servers.'
        Links        = @($plan.computer_ous.servers)
        LocalAdmins  = @($plan.local_admin_groups.servers)
    }
)

function Set-LabGpoFile {
    # Writes one file of a GPO in SYSVOL when its content differs, registers the client-side
    # extension, and raises the computer version so clients apply the change.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]$Gpo,
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][string[]]$Content,
        [Parameter(Mandatory)][string]$Encoding,
        [Parameter(Mandatory)][string]$Extension
    )
    $root = "\\$($Gpo.DomainName)\SYSVOL\$($Gpo.DomainName)\Policies\{$($Gpo.Id)}"
    $path = Join-Path $root $RelativePath
    if ((Test-Path -LiteralPath $path) -and
        ((Get-Content -LiteralPath $path -Encoding $Encoding) -join "`n") -eq ($Content -join "`n")) {
        return
    }
    if (-not $PSCmdlet.ShouldProcess($Gpo.DisplayName, "Write $RelativePath")) { return }

    New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
    Set-Content -LiteralPath $path -Value $Content -Encoding $Encoding

    $container = "CN={$($Gpo.Id)},CN=Policies,CN=System,$($plan.domain.dn)"
    $object = Get-ADObject -Identity $container -Properties versionNumber, gPCMachineExtensionNames
    $version = [int]$object.versionNumber + 1  # low 16 bits: computer version
    $extensions = Merge-LabExtensionName -Current $object.gPCMachineExtensionNames -Add $Extension
    Set-ADObject -Identity $container -Replace @{ versionNumber = $version; gPCMachineExtensionNames = $extensions }
    $gptIni = Join-Path $root 'GPT.INI'
    (Get-Content -LiteralPath $gptIni) -replace '^Version=\d+', "Version=$version" | Set-Content -LiteralPath $gptIni -Encoding Ascii
}

foreach ($definition in $gpos) {
    $gpo = Get-GPO -Name $definition.Name -ErrorAction SilentlyContinue
    if (-not $gpo) {
        if (-not $PSCmdlet.ShouldProcess($definition.Name, 'Create GPO')) { continue }  # -WhatIf
        $gpo = New-GPO -Name $definition.Name -Comment $definition.Comment
    }

    foreach ($setting in @($definition['Registry'] | Where-Object { $_ })) {
        $current = Get-GPRegistryValue -Name $gpo.DisplayName -Key $setting.Key -ValueName $setting.Name -ErrorAction SilentlyContinue
        if ((-not $current -or $current.Value -ne $setting.Value) -and
            $PSCmdlet.ShouldProcess($gpo.DisplayName, "Set $($setting.Key)\$($setting.Name) = $($setting.Value)")) {
            Set-GPRegistryValue -Name $gpo.DisplayName -Key $setting.Key -ValueName $setting.Name -Type DWord -Value $setting.Value | Out-Null
        }
    }

    $rights = @{}
    foreach ($entry in @($definition['PrivilegeRights'] | Where-Object { $_ })) {
        foreach ($right in $entry.Keys) { $rights[$right] = @($entry[$right] | ForEach-Object { Get-LabSid $_ }) }
    }
    $localGroups = @{}
    foreach ($group in @($definition['LocalAdmins'] | Where-Object { $_ })) { $localGroups[(Get-LabSid $group)] = @($administrators) }
    if ($rights.Count -gt 0 -or $localGroups.Count -gt 0) {
        Set-LabGpoFile -Gpo $gpo -RelativePath 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf' `
            -Content (ConvertTo-LabSecurityTemplate -PrivilegeRights $rights -LocalGroupMembers $localGroups) `
            -Encoding Unicode -Extension $LabCseSecurity
    }
    if ($definition['Audit']) {
        Set-LabGpoFile -Gpo $gpo -RelativePath 'Machine\Microsoft\Windows NT\Audit\audit.csv' `
            -Content (ConvertTo-LabAuditCsv -Subcategories $definition['Audit']) `
            -Encoding Ascii -Extension $LabCseAudit
    }

    foreach ($target in $definition.Links) {
        $linked = @((Get-GPInheritance -Target $target).GpoLinks | ForEach-Object { $_.DisplayName })
        if ($linked -notcontains $gpo.DisplayName -and $PSCmdlet.ShouldProcess($target, "Link $($gpo.DisplayName)")) {
            New-GPLink -Name $gpo.DisplayName -Target $target -LinkEnabled Yes | Out-Null
        }
    }
}

Write-Output 'GPOs are in place. Clients apply them at the next refresh (gpupdate /force to apply now).'
