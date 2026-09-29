<#
.SYNOPSIS
    Promotes DC01 to the first domain controller of the lab forest (phase 5).

.DESCRIPTION
    Run once on DC01, in an SSM session, before Invoke-ADProvisioning.ps1. The domain name comes
    from the generated plan (data/company.yaml). The Directory Services Restore Mode password is
    generated here and stored only in SSM Parameter Store. The server restarts when the forest is
    created.

.EXAMPLE
    .\Install-DomainController.ps1 -WhatIf
    .\Install-DomainController.ps1
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$PlanPath = (Join-Path $PSScriptRoot '..\generated\ad-plan.json'),
    [string]$Region = 'us-east-1',
    [string]$ParameterPrefix = '/moretti-group-lab/ad'
)

. (Join-Path $PSScriptRoot 'LabCommon.ps1')

$plan = Read-LabPlan -Path $PlanPath

if ((Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain) {
    Write-Output 'This server is already part of a domain: nothing to do.'
    return
}
if ($env:COMPUTERNAME -ne 'DC01') {
    throw "Run this script on DC01 (this computer is $env:COMPUTERNAME)."
}

$dsrm = Get-LabOrNewSecret -Name "$ParameterPrefix/dsrm" -Region $Region -Length 32

if ($PSCmdlet.ShouldProcess($plan.domain.fqdn, 'Install AD DS and create the forest (the server restarts)')) {
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools | Out-Null
    Install-ADDSForest `
        -DomainName $plan.domain.fqdn `
        -DomainNetbiosName $plan.domain.netbios `
        -InstallDns `
        -SafeModeAdministratorPassword (ConvertTo-LabSecureString -Value $dsrm) `
        -Force
}
