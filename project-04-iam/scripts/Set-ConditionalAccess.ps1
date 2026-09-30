<#
.SYNOPSIS
    Creates or updates the lab's Conditional Access policies in Entra ID from the generated JSON.

.DESCRIPTION
    Run on the operator's machine after Entra ID is set up and Cloud Sync has created the groups.
    Reads project-04-iam/generated/conditional-access-policies.json (generated from data/) and
    creates each policy by display name, or updates it if it already exists. Group and named-location
    references in the JSON are resolved to their tenant IDs; if any is missing, the policy is
    skipped with a message instead of failing the run.

    Policies are created in report-only state (as in the JSON). Re-run with -Enable to switch the
    lab policies to enabled once report-only has confirmed they behave as expected.

    Requires the Microsoft.Graph PowerShell module and a sign-in with Conditional Access admin
    rights:  Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess","Group.Read.All"

.EXAMPLE
    .\Set-ConditionalAccess.ps1 -WhatIf
    .\Set-ConditionalAccess.ps1
    .\Set-ConditionalAccess.ps1 -Enable
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$PolicyPath = (Join-Path $PSScriptRoot '..\generated\conditional-access-policies.json'),
    [switch]$Enable
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Get-MgContext)) {
    throw "Not connected. Run: Connect-MgGraph -Scopes 'Policy.ReadWrite.ConditionalAccess','Group.Read.All'"
}

$document = Get-Content -LiteralPath $PolicyPath -Raw -Encoding UTF8 | ConvertFrom-Json
$existing = @{}
foreach ($policy in Get-MgIdentityConditionalAccessPolicy -All) {
    $existing[$policy.DisplayName] = $policy.Id
}

function Resolve-LabGroupIdSet {
    param([string[]]$Names)
    $ids = @()
    foreach ($name in $Names) {
        $group = Get-MgGroup -Filter "displayName eq '$name'" -ConsistencyLevel eventual -CountVariable c -ErrorAction SilentlyContinue
        if (-not $group) { throw "group '$name' not found" }
        $ids += $group.Id
    }
    , $ids
}

foreach ($policy in $document.policies) {
    $name = $policy.displayName
    try {
        $users = $policy.conditions.users
        $body = @{
            displayName = $name
            state       = $Enable ? 'enabled' : $policy.state
            conditions  = @{
                users        = @{}
                applications = $policy.conditions.applications
            }
            grantControls = $policy.grantControls
        }
        if ($users.PSObject.Properties.Name -contains 'includeUsers') {
            $body.conditions.users.includeUsers = $users.includeUsers
        }
        if ($users.PSObject.Properties.Name -contains 'includeGroups') {
            $body.conditions.users.includeGroups = Resolve-LabGroupIdSet -Names $users.includeGroups
        }
        if ($users.PSObject.Properties.Name -contains 'excludeGroups') {
            $body.conditions.users.excludeGroups = Resolve-LabGroupIdSet -Names $users.excludeGroups
        }
    }
    catch {
        Write-Warning "Skipping '$name': $($_.Exception.Message). Create the group or named location first."
        continue
    }

    if ($existing.ContainsKey($name)) {
        if ($PSCmdlet.ShouldProcess($name, 'Update Conditional Access policy')) {
            Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $existing[$name] -BodyParameter $body
            Write-Output "updated: $name"
        }
    }
    elseif ($PSCmdlet.ShouldProcess($name, "Create Conditional Access policy ($($body.state))")) {
        New-MgIdentityConditionalAccessPolicy -BodyParameter $body | Out-Null
        Write-Output "created: $name ($($body.state))"
    }
}
