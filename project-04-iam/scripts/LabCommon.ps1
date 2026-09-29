# Shared helpers for the Moretti Group lab scripts (dot-sourced, not run directly).
# Target: Windows PowerShell 5.1 on Windows Server 2022, with the AWS Tools for PowerShell that
# ship with the AWS Windows AMIs. Passwords are never printed or written to disk: they go
# straight to SSM Parameter Store as SecureString (docs/lab-safety.md).

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Read-LabPlan {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Plan not found: $Path (download project-04-iam/generated/ad-plan.json first)."
    }
    Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Get-LabRandomIndex {
    # Uniform random index in [0, Max): rejection sampling avoids modulo bias.
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)][System.Security.Cryptography.RandomNumberGenerator]$Rng,
        [Parameter(Mandatory)][int]$Max
    )
    $bytes = New-Object byte[] 4
    $limit = [uint32]::MaxValue - ([uint32]::MaxValue % [uint32]$Max)
    do {
        $Rng.GetBytes($bytes)
        $value = [BitConverter]::ToUInt32($bytes, 0)
    } while ($value -ge $limit)
    [int]($value % [uint32]$Max)
}

function New-LabPassword {
    # Random password with at least one upper, lower, digit and symbol. No quotes, '$' or
    # backticks, so it can be pasted into any shell safely.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Generates a value; changes no state.')]
    [CmdletBinding()]
    [OutputType([string])]
    param([ValidateRange(16, 128)][int]$Length = 24)

    $sets = @('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!@#%^*()-_=+[]{}:,.?')
    $all = -join $sets
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $chars = New-Object System.Collections.Generic.List[char]
        foreach ($set in $sets) { $chars.Add($set[(Get-LabRandomIndex -Rng $rng -Max $set.Length)]) }
        while ($chars.Count -lt $Length) { $chars.Add($all[(Get-LabRandomIndex -Rng $rng -Max $all.Length)]) }
        for ($i = $chars.Count - 1; $i -gt 0; $i--) {
            # Fisher-Yates shuffle: the guaranteed characters do not always come first.
            $j = Get-LabRandomIndex -Rng $rng -Max ($i + 1)
            $swap = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $swap
        }
        -join $chars
    }
    finally {
        $rng.Dispose()
    }
}

function ConvertTo-LabSecureString {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '',
        Justification = 'The password is generated in memory by New-LabPassword or read from SSM.')]
    [CmdletBinding()]
    [OutputType([securestring])]
    param([Parameter(Mandatory)][string]$Value)
    ConvertTo-SecureString -String $Value -AsPlainText -Force
}

function Import-LabAwsTool {
    if (-not (Get-Command -Name Write-SSMParameter -ErrorAction SilentlyContinue)) {
        Import-Module AWSPowerShell
    }
}

function Get-LabSecret {
    # Value of a SecureString parameter, or $null when it does not exist yet.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Region)
    Import-LabAwsTool
    try {
        (Get-SSMParameter -Name $Name -WithDecryption $true -Region $Region).Value
    }
    catch {
        if ("$($_.Exception.GetType().Name) $($_.Exception.Message)" -match 'ParameterNotFound') { return $null }
        throw
    }
}

function Set-LabSecret {
    # Creates the parameter; never overwrites one, so a password is not lost by a second run.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Region
    )
    Import-LabAwsTool
    if ($PSCmdlet.ShouldProcess($Name, 'Store SecureString parameter')) {
        Write-SSMParameter -Name $Name -Value $Value -Type SecureString -Overwrite $false -Region $Region | Out-Null
    }
}

function Get-LabOrNewSecret {
    # The stored password of an account, generating and storing one on first use.
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Region,
        [int]$Length = 24
    )
    $value = Get-LabSecret -Name $Name -Region $Region
    if (-not $value) {
        $value = New-LabPassword -Length $Length
        Set-LabSecret -Name $Name -Value $value -Region $Region
    }
    $value
}
