<#
.SYNOPSIS
    Installs Sysmon and the Wazuh agent on a Windows lab host (DC01, WS-FIN01) and enrolls it.

.DESCRIPTION
    Run on the host, in an SSM session. The enrollment password is read from SSM Parameter Store
    (the host's role may read only that parameter) and written to the agent's authd.pass, never
    passed on the command line.

    Sysmon adds process, network and file events that the Security log does not have. Its
    configuration comes from a public community baseline; the script prints the SHA-256 of the
    file it used, so the validation record shows exactly which configuration ran.

.PARAMETER Version
    The manager's version (on SIEM01: /var/ossec/bin/wazuh-control info). An agent must never be
    newer than its manager.

.PARAMETER Groups
    Agent groups. DC01: 'windows,domain-controllers'.

.EXAMPLE
    .\Install-WazuhAgent.ps1 -Version 4.12.0 -Groups 'windows,domain-controllers'
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
    [string]$Groups = 'windows',
    [string]$Manager = '10.10.70.10',  # SIEM01 (data/assets.yaml)
    [string]$Region = 'us-east-1',
    [string]$EnrollmentParameter = '/moretti-group-lab/wazuh/enrollment-password',
    [string]$SysmonConfigUrl = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'  # Invoke-WebRequest is much faster without it

$work = Join-Path $env:TEMP 'moretti-wazuh'
New-Item -ItemType Directory -Force -Path $work | Out-Null

# ---------------------------------------------------------------------------- Sysmon
$config = Join-Path $work 'sysmonconfig.xml'
Invoke-WebRequest -Uri $SysmonConfigUrl -OutFile $config -UseBasicParsing
Write-Output "Sysmon configuration SHA-256: $((Get-FileHash -Path $config -Algorithm SHA256).Hash)"
if (Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue) {
    if ($PSCmdlet.ShouldProcess('Sysmon', 'Update configuration')) {
        & "$env:SystemRoot\Sysmon64.exe" -c $config | Out-Null
    }
}
elseif ($PSCmdlet.ShouldProcess('Sysmon', 'Install')) {
    Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile (Join-Path $work 'Sysmon.zip') -UseBasicParsing
    Expand-Archive -Path (Join-Path $work 'Sysmon.zip') -DestinationPath (Join-Path $work 'sysmon') -Force
    & (Join-Path $work 'sysmon\Sysmon64.exe') -accepteula -i $config | Out-Null
}

# ---------------------------------------------------------------------------- Wazuh agent
$agentDir = Join-Path ${env:ProgramFiles(x86)} 'ossec-agent'
if (-not (Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue)) {
    $msi = Join-Path $work "wazuh-agent-$Version-1.msi"
    Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-$Version-1.msi" -OutFile $msi -UseBasicParsing
    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Install Wazuh agent $Version (groups: $Groups)")) {
        $arguments = @('/i', "`"$msi`"", '/q', "WAZUH_MANAGER=$Manager", "WAZUH_AGENT_GROUP=$Groups", "WAZUH_AGENT_NAME=$env:COMPUTERNAME")
        $process = Start-Process -FilePath msiexec.exe -ArgumentList $arguments -Wait -PassThru
        if ($process.ExitCode -ne 0) { throw "msiexec failed with exit code $($process.ExitCode)." }
    }
}

if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Write the enrollment password and start the agent')) {
    if (-not (Get-Command -Name Get-SSMParameter -ErrorAction SilentlyContinue)) { Import-Module AWSPowerShell }
    $password = (Get-SSMParameter -Name $EnrollmentParameter -WithDecryption $true -Region $Region).Value
    $passwordFile = Join-Path $agentDir 'authd.pass'
    Set-Content -Path $passwordFile -Value $password -Encoding Ascii -NoNewline
    Remove-Variable -Name password
    # Only SYSTEM and Administrators may read it.
    & icacls.exe $passwordFile /inheritance:r /grant:r 'SYSTEM:F' 'Administrators:F' | Out-Null
    Start-Service -Name WazuhSvc
}

Remove-Item -Path $work -Recurse -Force
Write-Output "Done. On SIEM01, /var/ossec/bin/agent_control -l should list $env:COMPUTERNAME as Active."
