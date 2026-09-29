<#
.SYNOPSIS
    Joins a lab workstation (WS-FIN01) to the domain.

.DESCRIPTION
    Run on the workstation, in an SSM session, after DC01 is provisioned. The join uses the Tier 2
    endpoint administrator (delegated to join computers only in the Workstations OU), never a
    Domain Admin: a Tier 0 credential must not be typed on a workstation. The password is read
    from the console, not stored anywhere on this computer.

    Get the password on your Mac with:
        aws ssm get-parameter --with-decryption --query Parameter.Value --output text \
            --name /moretti-group-lab/ad/admins/adm-kelly.mattos

.EXAMPLE
    .\Join-LabDomain.ps1
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$DomainName = 'corp.moretti.internal',
    [string]$DnsServer = '10.10.80.10',
    [string]$OUPath = 'OU=Workstations,OU=Computers,OU=Moretti,DC=corp,DC=moretti,DC=internal',
    [string]$JoinAccount = 'adm-kelly.mattos'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ((Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain) {
    Write-Output 'This computer is already part of a domain: nothing to do.'
    return
}

$adapter = Get-NetAdapter | Where-Object Status -EQ 'Up' | Select-Object -First 1
if ($PSCmdlet.ShouldProcess($adapter.Name, "Use $DnsServer (DC01) as DNS server")) {
    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $DnsServer
}
Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$DomainName" -Type SRV -Server $DnsServer -DnsOnly |
    Out-Null  # fails here, with a clear error, if DC01 is not reachable

$password = Read-Host -Prompt "Password of $JoinAccount" -AsSecureString
$credential = New-Object System.Management.Automation.PSCredential("$JoinAccount@$DomainName", $password)

if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Join $DomainName in $OUPath and restart")) {
    Add-Computer -DomainName $DomainName -OUPath $OUPath -Credential $credential -Restart
}
