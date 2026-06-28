#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Provisions a low-privilege local 'ClaudeSandbox' for running Claude Code with
    scoped access to a fixed workspace directory, while denying access to the calling
    user's secrets.

.NOTES
    - Run from an ELEVATED PowerShell session.
    - Model: ClaudeSandbox is a STANDARD user. Windows default ACLs already deny it
      access to other users' profiles and admin areas. We GRANT the few extra
      paths it needs (sandbox workspace, its own profile) and add EXPLICIT DENY only on the
      current user's sensitive dirs as belt-and-suspenders.
    - VS + Git are assumed installed machine-wide (default). A Standard user can
      run them already; no extra grants needed for Program Files.
    - DENY ACEs override ALLOW. Review every Deny path before running.
    - The workspace config, setup marker, and Dev Shell bootstrap are generated
      into ProgramData (Users-traversable by default) and locked admin-write/
      Users-RX, so ClaudeSandbox can read/run them but not modify them.
    - The sandbox username and workspace directory name are baked in
      (ClaudeSandbox); they are not configurable.
    - The workspace base directory is prompted for interactively if not passed.
#>

[CmdletBinding()]
param(
    [string]$BasePath, # if omitted, you will be prompted
    [securestring]$Password # if omitted, you will be prompted
)

$ErrorActionPreference = 'Stop'

$UserName = 'ClaudeSandbox'   # baked in; not configurable
$SandboxDirectoryName = 'ClaudeSandbox'   # baked in; not configurable
$SetupVersion = 1
$ProgramDataRoot = 'C:\ProgramData\claude-win-sandbox'    # baked in; not configurable
$ConfigFile = Join-Path $ProgramDataRoot 'config.json'
$SetupMarkerFile = Join-Path $ProgramDataRoot 'setup-marker.json'
$BootstrapScript = 'C:\ProgramData\claude-win-sandbox\bootstrap\Enter-ClaudeDevShell.ps1'    # baked in; not configurable


function Write-Step { param($m) Write-Host "`n==> $m" -ForegroundColor Cyan }

# --- 0. Sanity ----------------------------------------------------------------
$callingUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name  # DOMAIN\user
$callingProfile = $env:USERPROFILE
Write-Step "Calling user: $callingUser"
Write-Step "Protecting profile: $callingProfile"

# --- 0b. Resolve sandbox workspace directory interactively -------------------
if (-not $BasePath) {
    $baseInput = Read-Host "Base directory for the sandbox workspace [C:\dev]"
    $BasePath = if ([string]::IsNullOrWhiteSpace($baseInput)) { 'C:\dev' } else { $baseInput.Trim() }
}
$SandboxPath = Join-Path $BasePath $SandboxDirectoryName
Write-Step "Sandbox workspace: $SandboxPath"

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

# --- 2. Shared workspace permissions -----------------------------------------
Write-Step "Configuring shared workspace at $SandboxPath"
if (-not (Test-Path $SandboxPath)) {
    New-Item -ItemType Directory -Path $SandboxPath -Force | Out-Null
    Write-Host "  created $SandboxPath" -ForegroundColor Green
}
# Grant calling user + ClaudeSandbox Modify on the workspace tree (inherited).
# Repos beneath this dir are covered by inheritance.
# Using icacls; (OI)(CI) = object + container inherit, M = Modify.
icacls $SandboxPath /grant "${callingUser}:(OI)(CI)M" | Out-Null
icacls $SandboxPath /grant "${UserName}:(OI)(CI)M"     | Out-Null
Write-Host "  granted Modify to $callingUser and $UserName" -ForegroundColor Green

# --- 3. Write ProgramData configuration --------------------------------------
# ProgramData config is the single source of truth for the sandbox path.
# ClaudeSandbox can read it at launch but cannot alter where the bootstrap lands.
Write-Step "Writing sandbox configuration and setup marker to ProgramData"
if (-not (Test-Path $ProgramDataRoot)) { New-Item -ItemType Directory -Path $ProgramDataRoot -Force | Out-Null }
$config = [ordered]@{
    sandboxPath = $SandboxPath
}
$config | ConvertTo-Json | Set-Content -Path $ConfigFile -Encoding UTF8
Write-Host "  wrote $ConfigFile" -ForegroundColor Green

$setupMarker = [ordered]@{
    setupVersion = $SetupVersion
    createdAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    userName = $UserName
    sandboxPath = $SandboxPath
    programDataRoot = $ProgramDataRoot
    configFile = $ConfigFile
    bootstrapScript = $BootstrapScript
}
$setupMarker | ConvertTo-Json | Set-Content -Path $SetupMarkerFile -Encoding UTF8
Write-Host "  wrote $SetupMarkerFile" -ForegroundColor Green

# --- 4. Verify the calling user's profile is not world/Users-readable --------
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

# --- 5. Verify VS Developer Shell + Git availability for the user ------------
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

# --- 6. Generate the Dev Shell bootstrap into ProgramData --------------------
# ProgramData is traversable by Users by default, so ClaudeSandbox can reach the
# bootstrap regardless of where this repo was cloned (no profile-traversal trap).
# We GENERATE it here and LOCK it admin-write / Users-RX, so the sandbox user can
# run it but cannot rewrite what executes at next launch.
Write-Step "Writing the Developer-Shell bootstrap to ProgramData"

$bootstrapDir = Split-Path $BootstrapScript -Parent
if (-not (Test-Path $bootstrapDir)) { New-Item -ItemType Directory -Path $bootstrapDir -Force | Out-Null }

# NOTE: expandable here-string (@"..."@) so $UserName and $ConfigFile are baked
# in at generation time. Runtime $-vars that must survive to execution are
# escaped as `$.
$configFileLiteral = $ConfigFile -replace "'", "''"
$bootstrap = @"
# VS Developer Shell + cd to sandbox workspace. Run AS ClaudeSandbox.
# Uses -VsInstanceId (more reliable than -VsInstallPath discovery under a
# different user profile). Errors loudly if VS isn't found.
`$ConfigFile = '$configFileLiteral'
if (-not (Test-Path `$ConfigFile)) {
    Write-Host "Sandbox config missing: `$ConfigFile" -ForegroundColor Red
    Write-Host "Run Setup-ClaudeSandbox.ps1 again." -ForegroundColor Yellow
    exit 1
}
try {
    `$config = Get-Content `$ConfigFile -Raw | ConvertFrom-Json
    `$SandboxPath = `$config.sandboxPath
}
catch {
    Write-Host "Sandbox config is invalid: `$(`$_.Exception.Message)" -ForegroundColor Red
    exit 1
}
if ([string]::IsNullOrWhiteSpace(`$SandboxPath)) {
    Write-Host "Sandbox config does not define sandboxPath." -ForegroundColor Red
    exit 1
}
if (-not (Test-Path `$SandboxPath)) {
    Write-Host "Sandbox path does not exist: `$SandboxPath" -ForegroundColor Red
    exit 1
}

# Guard: this must run as the sandbox user, not whoever launched it. If the
# bootstrap is invoked directly (no runas), refuse - running as the wrong user
# silently defeats the boundary.
`$me = (`$env:USERNAME)
if (`$me -ne '$UserName') {
    Write-Host "Refusing to run: expected user '$UserName' but running as '`$me'." -ForegroundColor Red
    Write-Host "Launch via Start-ClaudeSandbox.ps1 (which uses runas), not directly." -ForegroundColor Yellow
    exit 1
}
Write-Host "Running as `$me" -ForegroundColor Green

`$vs = & "`${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -format json | ConvertFrom-Json
Import-Module (Join-Path `$vs.installationPath 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll')
Enter-VsDevShell -VsInstanceId `$vs.instanceId -SkipAutomaticLocation -DevCmdArguments '-arch=x64'
Set-Location `$SandboxPath

# Ensure THIS user's per-user Claude install is on PATH. Self-contained: no
# dependency on the persisted User PATH. Prepend so the sandbox user's own copy
# wins over any machine-wide / other-profile install that may be on PATH - the
# install must live inside this profile to stay within the boundary.
`$claudeBin = Join-Path `$env:USERPROFILE '.local\bin'
if (Test-Path `$claudeBin) { `$env:PATH = "`$claudeBin;`$env:PATH" }

# Verify claude resolves; if not, tell the user how to install it (as THIS user).
if (Get-Command claude.exe -ErrorAction SilentlyContinue) {
    Write-Host "Ready in `$SandboxPath. Launch: claude" -ForegroundColor Cyan
}
else {
    Write-Host "Ready in `$SandboxPath, but 'claude' was not found." -ForegroundColor Yellow
    Write-Host "Install it AS THIS USER (do not use a machine-wide install):" -ForegroundColor Yellow
    Write-Host "  irm https://claude.ai/install.ps1 | iex" -ForegroundColor Cyan
    Write-Host "Then reopen this shell - the bootstrap puts `$claudeBin on PATH." -ForegroundColor DarkGray
}
"@
Set-Content -Path $BootstrapScript -Value $bootstrap -Encoding UTF8
Write-Host "  wrote $BootstrapScript" -ForegroundColor Green

# Lock ProgramData artifacts down: admin-write only, Users get read+execute
# (read/run but not modify). Mirrors the managed-settings.json lock so the
# sandbox user can't tamper with config or what runs at launch.
icacls $ProgramDataRoot /inheritance:r /grant 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' 'Users:(OI)(CI)RX' | Out-Null
icacls $bootstrapDir /inheritance:r /grant 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' 'Users:(OI)(CI)RX' | Out-Null
Write-Host "  locked ProgramData artifacts: Administrators/SYSTEM full, Users read+execute" -ForegroundColor Green

# --- 6b. Optional: desktop shortcut for double-click launch ------------------
Write-Step "Optional desktop shortcut"

$launcher = Join-Path $PSScriptRoot 'Start-ClaudeSandbox.ps1'
if (-not (Test-Path $launcher)) {
    Write-Warning "  Start-ClaudeSandbox.ps1 not found next to setup script - skipping shortcut."
}
else {
    $answer = Read-Host "Create a desktop shortcut to launch the sandbox? [Y/n]"
    if ($answer -match '^(n|no)$') {
        Write-Host "  skipped." -ForegroundColor Yellow
    }
    else {
        # Calling user's desktop (derived from their profile, not the elevated
        # process identity) vs. all-users Public desktop.
        $scope = Read-Host "Place on [c]alling-user desktop or [a]ll-users desktop? [C/a]"
        if ($scope -match '^(a|all)$') {
            $desktop = Join-Path $env:PUBLIC 'Desktop'
        }
        else {
            # $callingProfile = the invoking user's profile, captured in section 0.
            $desktop = Join-Path $callingProfile 'Desktop'
        }

        $lnkPath = Join-Path $desktop 'Claude (sandboxed).lnk'
        $wsh = New-Object -ComObject WScript.Shell
        $sc = $wsh.CreateShortcut($lnkPath)
        $sc.TargetPath = (Get-Command powershell.exe).Source
        $sc.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$launcher`""
        $sc.WorkingDirectory = $SandboxPath
        $sc.IconLocation = "$((Get-Command powershell.exe).Source),0"
        $sc.Description = 'Launch Claude Code as the low-privilege sandbox user'
        $sc.Save()

        Write-Host "  created $lnkPath" -ForegroundColor Green
    }
}

# --- 6. Done ------------------------------------------------------------------
Write-Step "Setup complete"
Write-Host @"
To start a Claude Code session, use the launcher:

  .\Start-ClaudeSandbox.ps1

(or directly: runas /user:$UserName "powershell -NoExit -File $BootstrapScript")

Notes:
  - Do NOT use runas /savecred (defeats the boundary).
  - Install Claude Code AS $UserName (irm https://claude.ai/install.ps1 | iex).
    A machine-wide or your-profile install can be picked up off the machine PATH
    and pulls binary/config from OUTSIDE the boundary - keep it per-user here.
  - ClaudeSandbox has its OWN Windows Credential Manager + profile. Set up its
    ADO PAT/git credential separately, scoped minimally. Your secrets are not
    visible to it.
  - ClaudeSandbox needs a writable home for ~/.claude config (its own profile -
    fine, contains none of your secrets).
"@ -ForegroundColor Cyan
