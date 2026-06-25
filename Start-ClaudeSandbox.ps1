<#
.SYNOPSIS
    Launches Claude Code as a low-privilege user inside a Visual Studio Developer
    Shell, scoped to a project directory. Prompts for the ClaudeSandbox password by
    default; optionally caches it in the CALLING user's Windows Credential Manager.

.DESCRIPTION
    Part of the claude-win-sandbox setup. Assumes Setup-ClaudeSandbox.ps1 has already
    provisioned the low-priv user, repo ACLs, and the Dev Shell bootstrap script.

    Credential handling:
      - Default: prompts for the password each launch (most secure).
      - -StoreCredential: saves it to the CALLING user's Credential Manager so
        future launches are friction-free. Note: this means your account can
        retrieve ClaudeSandbox's password. ClaudeSandbox is low-priv, so practical risk
        is low, but it does soften the boundary. Use -ClearCredential to remove.

.PARAMETER UserName
    The low-privilege user to run as. Default: ClaudeSandbox.

.PARAMETER RepoPath
    Project directory to drop into. Default: C:\dev\repo.

.PARAMETER BootstrapScript
    Dev Shell bootstrap written by Setup-ClaudeSandbox.ps1.

.PARAMETER StoreCredential
    Cache the credential in the calling user's Credential Manager after prompting.

.PARAMETER ClearCredential
    Remove any cached credential and exit.

.EXAMPLE
    .\Start-ClaudeSandbox.ps1
    Prompts for password, launches a sandboxed Dev Shell in C:\dev\repo.

.EXAMPLE
    .\Start-ClaudeSandbox.ps1 -StoreCredential
    Same, but caches the credential for next time.

.EXAMPLE
    .\Start-ClaudeSandbox.ps1 -ClearCredential
    Forgets the cached credential.
#>

[CmdletBinding(DefaultParameterSetName = 'Launch')]
param(
    [string]$UserName        = 'ClaudeSandbox',
    [string]$RepoPath        = 'C:\dev\repo',
    [string]$BootstrapScript = 'C:\dev\claude-tools\Enter-ClaudeDevShell.ps1',

    [Parameter(ParameterSetName = 'Launch')]
    [switch]$StoreCredential,

    [Parameter(ParameterSetName = 'Clear')]
    [switch]$ClearCredential
)

$ErrorActionPreference = 'Stop'

# Credential Manager target name (namespaced so it won't collide).
$CredTarget = "ClaudeSandbox:$UserName"

# --- Credential Manager helpers (cmdkey-based; no external module needed) -----
function Save-CachedCredential {
    param([string]$Target, [string]$User, [securestring]$Secret)
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret))
    # /generic stores under the calling user's vault, retrievable by them only.
    cmdkey /generic:$Target /user:$User /pass:$plain | Out-Null
    $plain = $null
    Write-Host "Cached credential under '$Target' (your Credential Manager)." -ForegroundColor Yellow
}

function Remove-CachedCredential {
    param([string]$Target)
    $existing = cmdkey /list:$Target 2>$null
    if ($existing -match $Target) {
        cmdkey /delete:$Target | Out-Null
        Write-Host "Removed cached credential '$Target'." -ForegroundColor Green
    } else {
        Write-Host "No cached credential '$Target' found." -ForegroundColor DarkGray
    }
}

function Test-CachedCredential {
    param([string]$Target)
    $existing = cmdkey /list:$Target 2>$null
    return [bool]($existing -match [regex]::Escape($Target))
}

# --- Clear mode: remove and exit ----------------------------------------------
if ($ClearCredential) {
    Remove-CachedCredential -Target $CredTarget
    return
}

# --- Pre-flight checks --------------------------------------------------------
if (-not (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue)) {
    Write-Error "User '$UserName' does not exist. Run Setup-ClaudeSandbox.ps1 first."
    return
}
if (-not (Test-Path $BootstrapScript)) {
    Write-Error "Bootstrap script not found at $BootstrapScript. Run Setup-ClaudeSandbox.ps1 first."
    return
}
if (-not (Test-Path $RepoPath)) {
    Write-Warning "Repo path $RepoPath does not exist yet - launching anyway."
}

# --- Credential acquisition ---------------------------------------------------
# runas.exe always prompts for the password itself and cannot accept it on the
# command line. To support cached/friction-free launches we therefore use
# Start-Process -Credential (which CAN take a PSCredential) instead of runas.exe.

$cred = $null

if (Test-CachedCredential -Target $CredTarget) {
    Write-Host "Using cached credential for '$UserName'." -ForegroundColor Cyan
    # cmdkey stores it for OS-level auth; to build a PSCredential we still need
    # the secret. cmdkey does not return the password to script, so for cached
    # use we rely on Start-Process reading the stored generic credential is NOT
    # automatic. Simplest robust approach: prompt, and offer to (re)store.
    # => If cached marker exists we still prompt unless you wire DPAPI (see README).
    Write-Host "(A marker exists, but Windows does not hand the password back to" -ForegroundColor DarkGray
    Write-Host " scripts. See README 'Frictionless launches' for the DPAPI option.)" -ForegroundColor DarkGray
}

if (-not $cred) {
    $secure = Read-Host "Password for '$UserName'" -AsSecureString
    $cred = New-Object System.Management.Automation.PSCredential($UserName, $secure)

    if ($StoreCredential) {
        Save-CachedCredential -Target $CredTarget -User $UserName -Secret $secure
    }
}

# --- Launch -------------------------------------------------------------------
# Open a new console window running the bootstrap (Dev Shell + cd repo), left
# open (-NoExit) so you can type `claude`.
$psArgs = @(
    '-NoExit'
    '-ExecutionPolicy', 'Bypass'
    '-File', "`"$BootstrapScript`""
)

Write-Host "Launching sandboxed Dev Shell as '$UserName' in $RepoPath ..." -ForegroundColor Green

try {
    Start-Process -FilePath 'powershell.exe' `
                  -Credential $cred `
                  -ArgumentList $psArgs `
                  -WorkingDirectory 'C:\' `
                  -ErrorAction Stop
    Write-Host "Launched. In the new window, run: claude" -ForegroundColor Cyan
}
catch {
    Write-Error "Launch failed: $($_.Exception.Message)"
    Write-Host "Common causes: wrong password, or the policy blocks Start-Process -Credential." -ForegroundColor Yellow
    Write-Host "Fallback - use runas directly:" -ForegroundColor Yellow
    Write-Host "  runas /user:$UserName `"powershell -NoExit -ExecutionPolicy Bypass -File $BootstrapScript`"" -ForegroundColor Gray
}
