<#
.SYNOPSIS
    Verifies a claude-win-sandbox installation: user, hardening, ACLs, policy,
    toolchain, and the assumptions the boundary depends on. Read-only - makes no
    changes. Safe to run anytime, including as a post-launch diagnostic.

.PARAMETER RepoPath
    Shared project directory. Default: C:\dev\repo.

.PARAMETER UserName
    Low-privilege sandbox user. Default: ClaudeSandbox.

.PARAMETER BootstrapScript
    Dev Shell bootstrap written by Setup-ClaudeSandbox.ps1.

.PARAMETER ManagedSettings
    Claude Code enterprise policy file.

.EXAMPLE
    .\Check-ClaudeSandbox.ps1
    Runs all checks and prints a PASS/WARN/FAIL summary.

.NOTES
    Exit code 0 if no FAILs, 1 if any FAIL. WARN does not fail the run.
    Some checks need elevation to read fully (e.g. user-rights, HKLM, other
    users' profiles); run elevated for complete results - the script notes where
    it's degraded.
#>

[CmdletBinding()]
param(
    [string]$RepoPath = 'C:\dev\repo',
    [string]$UserName = 'ClaudeSandbox',
    [string]$BootstrapScript = 'C:\ProgramData\claude-win-sandbox\bootstrap\Enter-ClaudeDevShell.ps1',
    [string]$ManagedSettings = 'C:\ProgramData\ClaudeCode\managed-settings.json'
)

$script:fails = 0
$script:warns = 0

function Pass { param($m) Write-Host "  [PASS] $m" -ForegroundColor Green }
function Warn { param($m) Write-Host "  [WARN] $m" -ForegroundColor Yellow; $script:warns++ }
function Fail { param($m) Write-Host "  [FAIL] $m" -ForegroundColor Red; $script:fails++ }
function Section { param($m) Write-Host "`n== $m ==" -ForegroundColor Cyan }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Note: not elevated - some checks (user-rights, HKLM, other profiles) may be limited." -ForegroundColor DarkYellow
}

# --- 1. User exists and is not admin -----------------------------------------
Section "User account"
$u = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
if (-not $u) {
    Fail "User '$UserName' does not exist. Run Setup-ClaudeSandbox.ps1."
    # Nothing else is meaningful without the user; print summary and exit.
    Write-Host "`nAborting remaining checks." -ForegroundColor Red
    exit 1
}
Pass "User '$UserName' exists."

if (-not $u.Enabled) { Warn "Account is disabled - launcher won't work until enabled." }
else { Pass "Account is enabled." }

$adminMembers = (Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue).Name
if ($adminMembers -match "\\$UserName$") { Fail "'$UserName' is in Administrators - should be Standard only." }
else { Pass "Not a member of Administrators." }

$userGroups = Get-LocalGroup | Where-Object {
    (Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue).Name -match "\\$UserName$"
}
$riskyGroups = $userGroups.Name | Where-Object { $_ -match 'Remote Desktop|Backup Operators|Power Users' }
if ($riskyGroups) { Warn "Member of elevated/remote groups: $($riskyGroups -join ', ')" }
else { Pass "No risky group memberships." }

# --- 2. Account hardening -----------------------------------------------------
Section "Account hardening"
if ($u.PasswordExpires) { Warn "Password is set to expire - may break launcher unexpectedly." }
else { Pass "Password never expires." }

if ($u.UserMayChangePassword) { Warn "User may change own password (no self-service needed)." }
else { Pass "User cannot change own password." }

# Deny network + RDP logon rights (read via secedit export; needs elevation).
if ($isAdmin) {
    try {
        $sid = $u.SID.Value
        $tmp = Join-Path $env:TEMP "claude_check_secpol.inf"
        secedit /export /cfg $tmp /areas USER_RIGHTS /quiet | Out-Null
        $pol = Get-Content $tmp
        Remove-Item $tmp -ErrorAction SilentlyContinue

        # secedit may record the account as *SID or by bare name - match either.
        $sidForm = [regex]::Escape("*$sid")
        $nameForm = "(^|[=,\s])$([regex]::Escape($UserName))([,\s]|$)"
        function Test-RightIncludesAccount {
            param([string]$Line, [string]$SidPattern, [string]$NamePattern)
            if (-not $Line) { return $false }
            $val = ($Line -split '=', 2)[1]
            return ($val -match $SidPattern) -or ($val -match $NamePattern)
        }

        foreach ($right in 'SeDenyNetworkLogonRight', 'SeDenyRemoteInteractiveLogonRight') {
            $line = $pol | Where-Object { $_ -match "^$right\s*=" }
            if (Test-RightIncludesAccount -Line $line -SidPattern $sidForm -NamePattern $nameForm) {
                Pass "$right includes the account."
            }
            else {
                Warn "$right does NOT include the account (run setup to apply)."
            }
        }
        # Sanity: interactive must NOT be denied, or the launcher breaks.
        $denyInteractive = $pol | Where-Object { $_ -match '^SeDenyInteractiveLogonRight\s*=' }
        if (Test-RightIncludesAccount -Line $denyInteractive -SidPattern $sidForm -NamePattern $nameForm) {
            Fail "Interactive logon is DENIED for the account - the launcher will not work."
        }
        else {
            Pass "Interactive logon is allowed (required by the launcher)."
        }
    }
    catch {
        Warn "Could not read user-rights policy: $($_.Exception.Message)"
    }
}
else {
    Warn "Skipped logon-rights checks (need elevation)."
}

# Hidden from login screen
$ualPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
$hidden = (Get-ItemProperty -Path $ualPath -Name $UserName -ErrorAction SilentlyContinue).$UserName
if ($hidden -eq 0) { Pass "Hidden from the login screen." }
else { Warn "Not hidden from the login screen (cosmetic)." }

# --- 3. Repo ACLs -------------------------------------------------------------
Section "Repo permissions ($RepoPath)"
if (-not (Test-Path $RepoPath)) {
    Warn "Repo path does not exist yet."
}
else {
    $acl = Get-Acl $RepoPath
    $userAce = $acl.Access | Where-Object { $_.IdentityReference -match "\\$UserName$" }
    if ($userAce | Where-Object { $_.FileSystemRights -match 'Modify|FullControl|Write' }) {
        Pass "'$UserName' has write access to the repo (and sub-repos, via inheritance)."
    }
    else {
        Fail "'$UserName' lacks write access to the repo - Claude can't edit code."
    }
}

# --- 4. Caller profile not world-readable ------------------------------------
Section "Your profile is not exposed"
$callingProfile = $env:USERPROFILE
$acl = Get-Acl $callingProfile
$risky = $acl.Access | Where-Object {
    $_.AccessControlType -eq 'Allow' -and
    $_.FileSystemRights -match 'Read|FullControl|Modify' -and
    $_.IdentityReference -match '\\(Users|Everyone|Authenticated Users)$|^Everyone$'
}
if ($risky) {
    Fail "Your profile grants broad read access: $(($risky.IdentityReference | Sort-Object -Unique) -join ', '). Fix the profile ACL."
}
else {
    Pass "Profile not readable by Users/Everyone - '$UserName' is denied by default."
}

# --- 5. Bootstrap + tooling ---------------------------------------------------
Section "Dev Shell bootstrap & toolchain"
if (Test-Path $BootstrapScript) {
    Pass "Bootstrap present: $BootstrapScript"

    # The bootstrap must be runnable by ClaudeSandbox but NOT writable by it -
    # otherwise the agent could rewrite what runs at next launch. Verify the dir
    # is admin-write / Users-RX (locked like managed-settings.json).
    $bootstrapDir = Split-Path $BootstrapScript -Parent
    $bacl = Get-Acl $bootstrapDir
    $writableByUsers = $bacl.Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and
        $_.FileSystemRights -match 'Write|Modify|FullControl' -and
        $_.IdentityReference -match '\\(Users|Everyone|Authenticated Users)$|^Everyone$'
    }
    if ($writableByUsers) {
        Fail "Bootstrap dir is writable by non-admins - $UserName could alter what runs at launch."
    }
    else {
        Pass "Bootstrap dir is admin-write-only (Users can run, not modify)."
    }
}
else {
    Fail "Bootstrap missing: $BootstrapScript - run setup."
}

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhere) {
    $vsPath = & $vswhere -latest -property installationPath 2>$null
    if ($vsPath -and (Test-Path (Join-Path $vsPath 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll'))) {
        Pass "VS Developer Shell found: $vsPath"
    }
    else { Warn "VS found but DevShell module missing." }
}
else { Warn "vswhere not found - is Visual Studio installed machine-wide?" }

if (Get-Command git.exe -ErrorAction SilentlyContinue) { Pass "git on machine PATH." }
else { Warn "git not on machine PATH." }

# --- 6. Claude Code install location -----------------------------------------
# The boundary depends on ClaudeSandbox running ITS OWN per-user copy, not one
# from your profile or a machine-wide install: either of those could be picked
# up off the machine PATH, pulling binary/config from outside the sandbox.
Section "Claude Code install"
$expected = "C:\Users\$UserName\.local\bin\claude.exe"
if (Test-Path $expected) { Pass "Claude Code installed for ${UserName}: $expected" }
else { Warn "No per-user Claude for $UserName at $expected - install AS $UserName (irm https://claude.ai/install.ps1 | iex)." }

# Flag installs OUTSIDE the sandbox user that could leak in via machine PATH.
$leaks = @()

# Other user profiles (needs elevation to traverse other users' dirs).
if ($isAdmin) {
    Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -ne $UserName } |
    ForEach-Object {
        $p = Join-Path $_.FullName '.local\bin\claude.exe'
        if (Test-Path $p) { $leaks += $p }
    }
}
else {
    Warn "Skipped other-profile scan (need elevation) - may under-report leaks."
}

# Machine-wide / common locations.
foreach ($m in @(
        "$env:ProgramFiles\Claude\claude.exe",
        "${env:ProgramFiles(x86)}\Claude\claude.exe",
        "$env:ProgramData\Claude\claude.exe"
    )) {
    if (Test-Path $m) { $leaks += $m }
}

# Anything resolvable on the check process's PATH that isn't the sandbox copy.
# (Resolves against you/admin, not ClaudeSandbox - catches machine/your-PATH leaks.)
$onPath = (Get-Command claude.exe -All -ErrorAction SilentlyContinue).Source |
Where-Object { $_ -and $_ -ne $expected }
if ($onPath) { $leaks += $onPath }

$leaks = $leaks | Sort-Object -Unique
if ($leaks) {
    Warn "Claude installed outside $UserName (could leak in via machine PATH):"
    $leaks | ForEach-Object { Warn "    $_" }
}
else {
    Pass "No Claude installs outside $UserName."
}

# --- 7. Claude Code managed policy -------------------------------------------
Section "Claude Code managed policy"
if (-not (Test-Path $ManagedSettings)) {
    Warn "Managed settings not found: $ManagedSettings - copy managed-settings.json there (see README)."
}
else {
    Pass "Policy file present."
    try {
        $json = Get-Content $ManagedSettings -Raw | ConvertFrom-Json
        if ($json.disableBypassPermissionsMode -eq 'disable') {
            Pass "Bypass-permissions mode is disabled."
        }
        else {
            Warn "Bypass-permissions mode is NOT disabled in policy."
        }
        if ($json.permissions.deny) { Pass "Deny rules present ($($json.permissions.deny.Count) entries)." }
        else { Warn "No deny rules in policy." }
    }
    catch {
        Fail "Policy file is not valid JSON: $($_.Exception.Message)"
    }
    # Policy file should be admin-write-only.
    $pacl = Get-Acl $ManagedSettings
    $writableByUsers = $pacl.Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and
        $_.FileSystemRights -match 'Write|Modify|FullControl' -and
        $_.IdentityReference -match '\\(Users|Everyone|Authenticated Users)$|^Everyone$'
    }
    if ($writableByUsers) { Fail "Policy file is writable by non-admins - ClaudeSandbox could disable it." }
    else { Pass "Policy file is admin-write-only." }
}

# --- Summary ------------------------------------------------------------------
Section "Summary"
if ($script:fails -eq 0 -and $script:warns -eq 0) {
    Write-Host "  All checks passed." -ForegroundColor Green
}
else {
    Write-Host "  $script:fails FAIL, $script:warns WARN." -ForegroundColor $(if ($script:fails) { 'Red' }else { 'Yellow' })
}
exit ([int]($script:fails -gt 0))
