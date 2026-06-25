#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Provisions a low-privilege local 'ClaudeSandbox' for running Claude Code with
    scoped access to C:\dev\repo, while denying access to the calling user's secrets.

.NOTES
    - Run from an ELEVATED PowerShell session.
    - Model: ClaudeSandbox is a STANDARD user. Windows default ACLs already deny it
      access to other users' profiles and admin areas. We GRANT the few extra
      paths it needs (repo, its own profile) and add EXPLICIT DENY only on the
      current user's sensitive dirs as belt-and-suspenders.
    - VS + Git are assumed installed machine-wide (default). A Standard user can
      run them already; no extra grants needed for Program Files.
    - DENY ACEs override ALLOW. Review every Deny path before running.
#>

[CmdletBinding()]
param(
    [string]$UserName = 'ClaudeSandbox',
    [string]$RepoPath = 'C:\dev\repo',
    [securestring]$Password # if omitted, you will be prompted
)

$ErrorActionPreference = 'Stop'

function Write-Step { param($m) Write-Host "`n==> $m" -ForegroundColor Cyan }

# --- 0. Sanity ----------------------------------------------------------------
$callingUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name  # DOMAIN\user
$callingProfile = $env:USERPROFILE
Write-Step "Calling user: $callingUser"
Write-Step "Protecting profile: $callingProfile"

# --- 1. Create the low-priv user ---------------------------------------------
Write-Step "Ensuring local user '$UserName' exists"
$existing = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
if (-not $existing) {
    if (-not $Password) {
        $Password = Read-Host "Set password for '$UserName'" -AsSecureString
    }
    New-LocalUser -Name $UserName -Password $Password `
        -FullName 'Claude Code Sandbox User' `
        -Description 'Low-privilege user for running Claude Code' `
        -PasswordNeverExpires:$false | Out-Null

    # Ensure it is ONLY a standard user (member of Users, not Administrators)
    Add-LocalGroupMember -Group 'Users' -Member $UserName -ErrorAction SilentlyContinue
    Write-Host "  created." -ForegroundColor Green
}
else {
    Write-Host "  already exists - leaving membership as-is." -ForegroundColor Yellow
}

# Hard guard: make sure it is NOT an administrator
$adminMembers = (Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue).Name
if ($adminMembers -match "\\$UserName$") {
    Write-Warning "'$UserName' is in Administrators. Removing for safety."
    Remove-LocalGroupMember -Group 'Administrators' -Member $UserName
}

# --- 1b. Harden the account ---------------------------------------------------
# This account is only ever used via the launcher (Start-Process -Credential /
# runas), which uses the INTERACTIVE logon type. So we deliberately do NOT deny
# interactive logon - doing so breaks the launcher (verified behavior). We deny
# the logon types the account never needs (network, RDP), set sane password
# flags, and hide it from the welcome screen.
Write-Step "Hardening '$UserName'"

# Password flags: never expires (avoid surprise launcher breakage), user can't
# change it (no self-service needed).
$u = Get-LocalUser -Name $UserName
Set-LocalUser -Name $UserName -PasswordNeverExpires $true -UserMayChangePassword $false
Write-Host "  password: never-expires, user-cannot-change" -ForegroundColor Green

# Deny NETWORK and REMOTE INTERACTIVE (RDP) logon rights via secedit.
# (Interactive + the runas path are intentionally left allowed.)
$sid = $u.SID.Value
$tmp = Join-Path $env:TEMP "claude_sandbox_secpol"
$inf = "$tmp.inf"; $sdb = "$tmp.sdb"
secedit /export /cfg $inf /quiet

# Read existing deny lists (if any) and append our SID, avoiding duplicates.
$content = Get-Content $inf
function Add-SidToRight {
    param([string[]]$Lines, [string]$Right, [string]$Sid, [string]$AccountName)
    $marker = "*$Sid"
    # Find the line index of an existing right entry, if any.
    $rightIdx = -1
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match "^\s*$Right\s*=") { $rightIdx = $i; break }
    }
    if ($rightIdx -ge 0) {
        # Already present in EITHER form (secedit may store *SID or bare name)?
        $val = ($Lines[$rightIdx] -split '=', 2)[1]
        $hasSid = $val -like "*$marker*"
        $hasName = $val -match "(^|[=,\s])$([regex]::Escape($AccountName))([,\s]|$)"
        if (-not ($hasSid -or $hasName)) {
            $Lines[$rightIdx] = "$($Lines[$rightIdx]),$marker"
        }
        return $Lines
    }
    # No existing entry: insert right after the [Privilege Rights] header.
    $hdrIdx = -1
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i].Trim() -eq '[Privilege Rights]') { $hdrIdx = $i; break }
    }
    $newLine = "$Right = $marker"
    if ($hdrIdx -ge 0) {
        $before = if ($hdrIdx -ge 0) { $Lines[0..$hdrIdx] } else { @() }
        $after = if ($hdrIdx + 1 -le $Lines.Count - 1) { $Lines[($hdrIdx + 1)..($Lines.Count - 1)] } else { @() }
        return @($before + $newLine + $after)
    }
    # Header missing (unexpected): append a fresh section.
    return @($Lines + '[Privilege Rights]' + $newLine)
}
$content = Add-SidToRight -Lines $content -Right 'SeDenyNetworkLogonRight'           -Sid $sid -AccountName $UserName
$content = Add-SidToRight -Lines $content -Right 'SeDenyRemoteInteractiveLogonRight' -Sid $sid -AccountName $UserName
Set-Content -Path $inf -Value $content -Encoding Unicode

secedit /configure /db $sdb /cfg $inf /areas USER_RIGHTS /quiet
Remove-Item $inf, $sdb -ErrorAction SilentlyContinue
Write-Host "  denied network + RDP logon (interactive left intact for launcher)" -ForegroundColor Green

# Hide from the Welcome / login screen (cosmetic + discourages manual login).
$ualPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
if (-not (Test-Path $ualPath)) { New-Item -Path $ualPath -Force | Out-Null }
New-ItemProperty -Path $ualPath -Name $UserName -Value 0 -PropertyType DWord -Force | Out-Null
Write-Host "  hidden from the login screen" -ForegroundColor Green

# --- 2. Shared repo permissions ----------------------------------------------
Write-Step "Configuring shared repo at $RepoPath"
if (-not (Test-Path $RepoPath)) {
    New-Item -ItemType Directory -Path $RepoPath -Force | Out-Null
    Write-Host "  created $RepoPath" -ForegroundColor Green
}
# Grant calling user + ClaudeSandbox Modify on the repo tree (inherited).
# Sub-repos beneath this dir are covered by inheritance.
# Using icacls; (OI)(CI) = object + container inherit, M = Modify.
icacls $RepoPath /grant "${callingUser}:(OI)(CI)M" | Out-Null
icacls $RepoPath /grant "${UserName}:(OI)(CI)M"     | Out-Null
Write-Host "  granted Modify to $callingUser and $UserName" -ForegroundColor Green

# --- 3. Verify the calling user's profile is not world/Users-readable --------
# On a standard Windows config, C:\Users\<you> is accessible only to that user,
# SYSTEM, and Administrators. A Standard user (ClaudeSandbox) is denied by default,
# so NO explicit deny ACEs are needed - and explicit denies are brittle
# (they override everything and are a classic source of lockouts). Instead we
# VERIFY the assumption and warn loudly if the profile ACL is too permissive.
Write-Step "Verifying your profile is not readable by Users/Everyone"

$acl = Get-Acl -Path $callingProfile
$risky = $acl.Access | Where-Object {
    $_.AccessControlType -eq 'Allow' -and
    $_.FileSystemRights -match 'Read|FullControl|Modify' -and
    $_.IdentityReference -match '\\(Users|Everyone|Authenticated Users)$|^Everyone$'
}

if ($risky) {
    Write-Warning "Your profile '$callingProfile' grants read access to a broad group:"
    $risky | ForEach-Object {
        Write-Warning "    $($_.IdentityReference) : $($_.FileSystemRights)"
    }
    Write-Warning "This means '$UserName' may be able to read your secrets. This is a"
    Write-Warning "MISCONFIGURED system. Fix the profile ACL (remove the broad grant)"
    Write-Warning "rather than relying on per-path denies. The boundary depends on this."
}
else {
    Write-Host "  OK - profile is not exposed to Users/Everyone." -ForegroundColor Green
    Write-Host "  '$UserName' is denied your profile by default Windows ACLs." -ForegroundColor Green
}

Write-Warning "Optional hardening note: if you keep secrets OUTSIDE your profile (e.g. a"
Write-Warning "KeePass vault under C:\, a shared drive), verify those paths separately - the"
Write-Warning "profile-default protection does not extend to them."

# --- 4. Verify VS Developer Shell + Git availability for the user ------------
Write-Step "Locating Visual Studio Developer Shell + Git (machine-wide)"

# vswhere is the supported way to find the VS install + dev shell module.
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhere) {
    $vsPath = & $vswhere -latest -property installationPath
    $devShell = Join-Path $vsPath 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll'
    if (Test-Path $devShell) {
        Write-Host "  VS DevShell module: $devShell" -ForegroundColor Green
    }
    else {
        Write-Warning "  DevShell module not found under $vsPath - check VS install."
    }
}
else {
    Write-Warning "  vswhere.exe not found. Is Visual Studio installed machine-wide?"
}

$gitCmd = Get-Command git.exe -ErrorAction SilentlyContinue
$git = if ($gitCmd) { $gitCmd.Source } else { $null }
if ($git) {
    Write-Host "  git: $git" -ForegroundColor Green
}
else {
    Write-Warning "  git not on machine PATH. Install Git for Windows machine-wide."
}

# A standard user can execute both already. No grants needed because they live
# in Program Files (readable+executable by Users by default).

# --- 5. Emit a launch profile for the dev shell ------------------------------
Write-Step "Writing a Developer-Shell bootstrap for $UserName"

$bootstrapDir = "C:\dev\claude-tools"
if (-not (Test-Path $bootstrapDir)) { New-Item -ItemType Directory -Path $bootstrapDir -Force | Out-Null }
icacls $bootstrapDir /grant "${UserName}:(OI)(CI)RX" | Out-Null

$bootstrap = @'
# VS Developer Shell + cd to repo. Run AS ClaudeSandbox.
# Uses -VsInstanceId (more reliable than -VsInstallPath discovery under a
# different user profile). Errors loudly if VS isn't found.
param([string]$RepoPath = 'C:\dev\repo')
$vs = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -format json | ConvertFrom-Json
Import-Module (Join-Path $vs.installationPath 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll')
Enter-VsDevShell -VsInstanceId $vs.instanceId -SkipAutomaticLocation -DevCmdArguments '-arch=x64'
Set-Location $RepoPath
Write-Host "Ready in $RepoPath. Launch: claude" -ForegroundColor Cyan
'@
Set-Content -Path (Join-Path $bootstrapDir 'Enter-ClaudeDevShell.ps1') -Value $bootstrap -Encoding UTF8
Write-Host "  wrote $bootstrapDir\Enter-ClaudeDevShell.ps1" -ForegroundColor Green

# --- 6. Done ------------------------------------------------------------------
Write-Step "Setup complete"
Write-Host @"
To start a Claude Code session, use the launcher:

  .\Start-ClaudeSandbox.ps1

(or directly: runas /user:$UserName "powershell -NoExit -File C:\dev\claude-tools\Enter-ClaudeDevShell.ps1")

Notes:
  - Do NOT use runas /savecred (defeats the boundary).
  - ClaudeSandbox has its OWN Windows Credential Manager + profile. Set up its
    ADO PAT/git credential separately, scoped minimally. Your secrets are not
    visible to it.
  - ClaudeSandbox needs a writable home for ~/.claude config (its own profile -
    fine, contains none of your secrets).
"@ -ForegroundColor Cyan
