# Builds the Group Policy files that have no PowerShell cmdlet: the security template
# (GptTmpl.inf: user rights and group membership) and the advanced audit policy (audit.csv).
# Pure functions, dot-sourced by New-LabGpos.ps1 and tested by tests/Test-GpoTemplates.ps1.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '',
    Justification = 'Constants read by the scripts that dot-source this file.')]
param()

# Client-side extension pairs that tell Windows which parts of a GPO to process.
$LabCseSecurity = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'
$LabCseAudit = '[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]'

# Advanced audit subcategories the SOC relies on (phase 6). Setting: 1 success, 2 failure, 3 both.
$LabAuditSubcategories = @(
    @{ Name = 'Audit Credential Validation'; Guid = '{0cce923f-69ae-11d9-bed3-505054503030}'; Setting = 3 }        # 4776
    @{ Name = 'Audit Kerberos Authentication Service'; Guid = '{0cce9242-69ae-11d9-bed3-505054503030}'; Setting = 3 }  # 4768, 4771
    @{ Name = 'Audit Kerberos Service Ticket Operations'; Guid = '{0cce9240-69ae-11d9-bed3-505054503030}'; Setting = 3 } # 4769
    @{ Name = 'Audit User Account Management'; Guid = '{0cce9235-69ae-11d9-bed3-505054503030}'; Setting = 3 }      # 4720, 4722, 4725, 4726, 4738, 4740
    @{ Name = 'Audit Security Group Management'; Guid = '{0cce9237-69ae-11d9-bed3-505054503030}'; Setting = 1 }    # 4728, 4732, 4756
    @{ Name = 'Audit Logon'; Guid = '{0cce9215-69ae-11d9-bed3-505054503030}'; Setting = 3 }                        # 4624, 4625
    @{ Name = 'Audit Account Lockout'; Guid = '{0cce9217-69ae-11d9-bed3-505054503030}'; Setting = 2 }              # 4625 (locked)
    @{ Name = 'Audit Special Logon'; Guid = '{0cce921b-69ae-11d9-bed3-505054503030}'; Setting = 1 }                # 4672
    @{ Name = 'Audit Process Creation'; Guid = '{0cce922b-69ae-11d9-bed3-505054503030}'; Setting = 1 }             # 4688
)

function ConvertTo-LabSecurityTemplate {
    # GptTmpl.inf content. PrivilegeRights: right name -> SIDs. LocalGroupMembers: SID of a
    # domain group -> SIDs of the local groups it is added to (additive: existing members stay).
    [CmdletBinding()]
    [OutputType([System.Array])]
    param([hashtable]$PrivilegeRights = @{}, [hashtable]$LocalGroupMembers = @{})

    $lines = @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1')
    if ($PrivilegeRights.Count -gt 0) {
        $lines += '[Privilege Rights]'
        foreach ($right in ($PrivilegeRights.Keys | Sort-Object)) {
            $lines += "$right = " + (($PrivilegeRights[$right] | ForEach-Object { "*$_" }) -join ',')
        }
    }
    if ($LocalGroupMembers.Count -gt 0) {
        $lines += '[Group Membership]'
        foreach ($member in ($LocalGroupMembers.Keys | Sort-Object)) {
            $lines += "*$($member)__Memberof = " + (($LocalGroupMembers[$member] | ForEach-Object { "*$_" }) -join ',')
            $lines += "*$($member)__Members ="
        }
    }
    , $lines
}

function ConvertTo-LabAuditCsv {
    [CmdletBinding()]
    [OutputType([System.Array])]
    param([Parameter(Mandatory)][object[]]$Subcategories)
    $labels = @{ 1 = 'Success'; 2 = 'Failure'; 3 = 'Success and Failure' }
    $lines = @('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value')
    foreach ($item in $Subcategories) {
        $lines += ",System,$($item.Name),$($item.Guid),$($labels[[int]$item.Setting]),,$($item.Setting)"
    }
    , $lines
}

function Merge-LabExtensionName {
    # gPCMachineExtensionNames with the given pairs added: unique, sorted as Windows expects.
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$Current, [Parameter(Mandatory)][string[]]$Add)
    $pairs = @([regex]::Matches("$Current", '\[[^\]]+\]') | ForEach-Object { $_.Value }) + $Add
    -join ($pairs | ForEach-Object { $_.ToUpperInvariant() } | Sort-Object -Unique)
}
