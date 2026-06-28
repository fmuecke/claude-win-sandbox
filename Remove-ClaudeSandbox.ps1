#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Removes the local ClaudeSandbox account and claude-win-sandbox ProgramData
    state.

.DESCRIPTION
    This is the teardown counterpart to Setup-ClaudeSandbox.ps1. It removes the
    fixed ClaudeSandbox local user, account-scoped firewall rules, account logon
    hardening entries, the hidden-login-screen registry value, and the generated
    ProgramData files under C:\ProgramData\claude-win-sandbox.

    It deliberately does NOT delete the shared sandbox workspace directory. The
    script removes the ClaudeSandbox ACL grant from that directory when it can
    resolve the path from ProgramData config or -SandboxPath. Delete the
    workspace manually if it is no longer needed.

.PARAMETER SandboxPath
    Optional workspace path used for ACL cleanup when ProgramData config has
    already been removed or is unreadable.

.PARAMETER Force
    Skip the interactive confirmation prompt.

.EXAMPLE
    .\Remove-ClaudeSandbox.ps1

.EXAMPLE
    .\Remove-ClaudeSandbox.ps1 -SandboxPath C:\dev\ClaudeSandbox -Force
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$SandboxPath,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

$UserName = 'ClaudeSandbox'   # baked in; not configurable
$SandboxDirectoryName = 'ClaudeSandbox'   # baked in; not configurable
$ProgramDataRoot = 'C:\ProgramData\claude-win-sandbox'    # baked in; not configurable
$ConfigFile = Join-Path $ProgramDataRoot 'config.json'
$SetupMarkerFile = Join-Path $ProgramDataRoot 'setup-marker.json'
$FirewallRuleGroup = 'claude-win-sandbox'
$FirewallRuleNames = @(
    'claude_win_sandbox_block_smb_netbios_tcp',
    'claude_win_sandbox_block_netbios_udp',
    'claude_win_sandbox_block_remote_admin_tcp'
)

function Write-Step { param($m) Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Removed { param($m) Write-Host "  removed $m" -ForegroundColor Green }
function Write-Skipped { param($m) Write-Host "  skipped $m" -ForegroundColor Yellow }

function Get-ConfiguredSandboxPath {
    param([string]$FallbackPath)

    if (-not [string]::IsNullOrWhiteSpace($FallbackPath)) {
        return $FallbackPath
    }

    foreach ($stateFile in @($ConfigFile, $SetupMarkerFile)) {
        if (-not (Test-Path $stateFile)) {
            continue
        }

        try {
            $state = Get-Content $stateFile -Raw | ConvertFrom-Json
            if (-not [string]::IsNullOrWhiteSpace($state.sandboxPath)) {
                return [string]$state.sandboxPath
            }
        }
        catch {
            Write-Warning "Could not read sandbox path from ${stateFile}: $($_.Exception.Message)"
        }
    }

    return $null
}

function Remove-PrincipalFromRight {
    param(
        [string[]]$Lines,
        [string]$Right,
        [string]$Sid,
        [string]$AccountName
    )

    $result = New-Object System.Collections.Generic.List[string]
    $rightPattern = "^\s*$([regex]::Escape($Right))\s*="

    foreach ($line in $Lines) {
        if ($line -notmatch $rightPattern) {
            $result.Add($line)
            continue
        }

        $value = ($line -split '=', 2)[1]
        $kept = @()
        foreach ($entry in ($value -split ',')) {
            $token = $entry.Trim()
            if ([string]::IsNullOrWhiteSpace($token)) {
                continue
            }

            $isSidMatch = -not [string]::IsNullOrWhiteSpace($Sid) -and (
                $token -eq "*$Sid" -or
                $token -eq $Sid
            )
            $isNameMatch = (
                $token -eq $AccountName -or
                $token -match "\\$([regex]::Escape($AccountName))$"
            )

            if (-not ($isSidMatch -or $isNameMatch)) {
                $kept += $token
            }
        }

        if ($kept.Count -gt 0) {
            $result.Add("$Right = $($kept -join ',')")
        }
    }

    return $result.ToArray()
}

function Remove-SandboxUserRights {
    param(
        [string]$Sid,
        [string]$AccountName
    )

    $tmpBase = Join-Path $env:TEMP "claude_sandbox_remove_secpol_$([guid]::NewGuid().ToString('N'))"
    $inf = "$tmpBase.inf"
    $sdb = "$tmpBase.sdb"

    try {
        secedit /export /cfg $inf /quiet | Out-Null
        $content = Get-Content $inf
        $updated = Remove-PrincipalFromRight -Lines $content -Right 'SeDenyNetworkLogonRight' -Sid $Sid -AccountName $AccountName
        $updated = Remove-PrincipalFromRight -Lines $updated -Right 'SeDenyRemoteInteractiveLogonRight' -Sid $Sid -AccountName $AccountName

        if (($content -join "`n") -eq ($updated -join "`n")) {
            Write-Skipped "user-rights cleanup (no entries found)"
            return
        }

        if ($PSCmdlet.ShouldProcess('local security policy', "Remove deny-logon rights for $AccountName")) {
            Set-Content -Path $inf -Value $updated -Encoding Unicode
            secedit /configure /db $sdb /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
            Write-Removed "deny-logon rights for $AccountName"
        }
    }
    catch {
        Write-Warning "Could not clean local security policy entries: $($_.Exception.Message)"
    }
    finally {
        Remove-Item $inf, $sdb -ErrorAction SilentlyContinue
    }
}

function Remove-SandboxWorkspaceAccess {
    param(
        [string]$Path,
        [string]$AccountName,
        [string]$Sid
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        Write-Skipped "workspace ACL cleanup (sandbox path unknown)"
        return
    }

    if ((Split-Path $Path -Leaf) -ne $SandboxDirectoryName) {
        Write-Warning "Refusing workspace ACL cleanup because path does not end in '$SandboxDirectoryName': $Path"
        return
    }

    if (-not (Test-Path $Path)) {
        Write-Skipped "workspace ACL cleanup ($Path not found)"
        return
    }

    $principals = @($AccountName)
    if (-not [string]::IsNullOrWhiteSpace($Sid)) {
        $principals += "*$Sid"
    }
    $principals = @($principals | Select-Object -Unique)
    $removedAny = $false

    foreach ($principal in $principals) {
        foreach ($removeMode in @('/remove:g', '/remove:d')) {
            if ($PSCmdlet.ShouldProcess("$Path ACL", "Remove $removeMode entries for $principal")) {
                & icacls $Path $removeMode $principal | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    Write-Warning "icacls returned exit code $LASTEXITCODE while removing $principal from $Path"
                }
                else {
                    $removedAny = $true
                }
            }
        }
    }

    if ($removedAny) {
        Write-Removed "workspace ACL entries for $AccountName from $Path"
    }
}

function Remove-SandboxFirewallRules {
    $rules = @()

    foreach ($ruleName in $FirewallRuleNames) {
        $rule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
        if ($rule) {
            $rules += $rule
        }
    }

    $groupRules = @(Get-NetFirewallRule -Group $FirewallRuleGroup -ErrorAction SilentlyContinue)
    if ($groupRules) {
        $rules += $groupRules
    }

    $rules = @($rules | Sort-Object -Property Name -Unique)
    if ($rules.Count -eq 0) {
        Write-Skipped "firewall rules (none found)"
        return
    }

    foreach ($rule in $rules) {
        if ($PSCmdlet.ShouldProcess("firewall rule '$($rule.Name)'", 'Remove')) {
            Remove-NetFirewallRule -InputObject $rule
            Write-Removed "firewall rule: $($rule.DisplayName)"
        }
    }
}

function Remove-SandboxLoginScreenEntry {
    $ualPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
    if (-not (Test-Path $ualPath)) {
        Write-Skipped "hidden-login-screen registry cleanup (key not found)"
        return
    }

    $value = Get-ItemProperty -Path $ualPath -Name $UserName -ErrorAction SilentlyContinue
    if (-not $value) {
        Write-Skipped "hidden-login-screen registry cleanup (value not found)"
        return
    }

    if ($PSCmdlet.ShouldProcess("$ualPath\$UserName", 'Remove registry value')) {
        Remove-ItemProperty -Path $ualPath -Name $UserName
        Write-Removed "hidden-login-screen registry value"
    }
}

# --- 0. Resolve current state -------------------------------------------------
$ResolvedSandboxPath = Get-ConfiguredSandboxPath -FallbackPath $SandboxPath
$user = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
$sid = if ($user) { $user.SID.Value } else { $null }

Write-Step "Removal target summary"
Write-Host "  user: $UserName"
Write-Host "  ProgramData: $ProgramDataRoot"
if ([string]::IsNullOrWhiteSpace($ResolvedSandboxPath)) {
    Write-Host "  workspace: unknown (pass -SandboxPath to remove stale ACLs)" -ForegroundColor Yellow
}
else {
    Write-Host "  workspace: $ResolvedSandboxPath (contents will NOT be deleted)" -ForegroundColor Yellow
}

if (-not $Force -and -not $WhatIfPreference) {
    Write-Host ''
    Write-Host 'This removes the sandbox user and ProgramData state, but leaves the shared workspace directory intact.' -ForegroundColor Yellow
    $answer = Read-Host "Type REMOVE to continue"
    if ($answer -ne 'REMOVE') {
        Write-Host 'Cancelled.' -ForegroundColor Yellow
        exit 1
    }
}

# --- 1. Remove workspace ACL grant before deleting the user ------------------
Write-Step "Removing workspace access for '$UserName'"
Remove-SandboxWorkspaceAccess -Path $ResolvedSandboxPath -AccountName $UserName -Sid $sid

# --- 2. Remove account-scoped hardening artifacts ----------------------------
Write-Step "Removing account-scoped firewall rules"
Remove-SandboxFirewallRules

Write-Step "Removing local security policy entries"
Remove-SandboxUserRights -Sid $sid -AccountName $UserName

Write-Step "Removing login-screen hiding entry"
Remove-SandboxLoginScreenEntry

# --- 3. Remove the local sandbox user ----------------------------------------
Write-Step "Removing local user '$UserName'"
if ($user) {
    if ($PSCmdlet.ShouldProcess("local user '$UserName'", 'Remove')) {
        Remove-LocalUser -Name $UserName
        Write-Removed "local user '$UserName'"
    }
}
else {
    Write-Skipped "local user '$UserName' (not found)"
}

# --- 4. Remove generated ProgramData files -----------------------------------
Write-Step "Removing ProgramData sandbox files"
if (Test-Path $ProgramDataRoot) {
    if ($PSCmdlet.ShouldProcess($ProgramDataRoot, 'Remove generated ProgramData files recursively')) {
        Remove-Item -LiteralPath $ProgramDataRoot -Recurse -Force
        Write-Removed $ProgramDataRoot
    }
}
else {
    Write-Skipped "$ProgramDataRoot (not found)"
}

# --- 5. Done ------------------------------------------------------------------
Write-Step "Removal complete"
$workspaceMessage = if ([string]::IsNullOrWhiteSpace($ResolvedSandboxPath)) {
    '  (unknown - ProgramData state was missing and -SandboxPath was not provided)'
}
else {
    "  $ResolvedSandboxPath"
}
Write-Host @"
The shared sandbox workspace was not deleted:

$workspaceMessage

Delete that directory manually if it is no longer needed. It is a shared space,
so this script only removes the sandbox user's access grant and leaves contents
for human review.
"@ -ForegroundColor Cyan
