<#
.SYNOPSIS
    Launches Claude Code as a low-privilege user inside a Visual Studio Developer
    Shell, scoped to a project directory. Prompts for the password each launch.

.DESCRIPTION
    Part of claude-win-sandbox. Assumes Setup-ClaudeSandbox.ps1 has provisioned
    the low-priv user, repo ACLs, and the Dev Shell bootstrap.

    Launch uses runas.exe, which attaches the new process to an interactive
    desktop for the target user so the console accepts keyboard input.
    (Start-Process -Credential can produce a window that renders but won't accept
    typing - the "hung shell".) runas prompts for the password natively.

.PARAMETER RepoPath
    Project directory to drop into. Default: C:\dev\ClaudeSandbox.

.PARAMETER UserName
    The low-privilege user to run as. Default: ClaudeSandbox.

.PARAMETER BootstrapScript
    Dev Shell bootstrap written by Setup-ClaudeSandbox.ps1.

.EXAMPLE
    .\Start-ClaudeSandbox.ps1
    Prompts for the password, launches a sandboxed Dev Shell in C:\dev\ClaudeSandbox.

.EXAMPLE
    .\Start-ClaudeSandbox.ps1 -RepoPath C:\dev\other
    Same, but drops into a different directory.
#>

[CmdletBinding()]
param(
    [string]$RepoPath = 'C:\dev\ClaudeSandbox',
    [string]$UserName = 'ClaudeSandbox',
    [string]$BootstrapScript = 'C:\ProgramData\claude-win-sandbox\bootstrap\Enter-ClaudeDevShell.ps1'
)

$ErrorActionPreference = 'Stop'

# --- Pre-flight checks --------------------------------------------------------
if (-not (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue)) {
    Write-Error "User '$UserName' does not exist. Run Setup-ClaudeSandbox.ps1 first."
    return
}
if (-not (Test-Path $BootstrapScript)) {
    Write-Error "Bootstrap not found at $BootstrapScript. Run Setup-ClaudeSandbox.ps1 first."
    return
}
if (-not (Test-Path $RepoPath)) {
    Write-Warning "Repo path $RepoPath does not exist yet - launching anyway."
}

# --- Launch -------------------------------------------------------------------
$inner = "powershell.exe -NoExit -ExecutionPolicy Bypass -File `"$BootstrapScript`" -RepoPath `"$RepoPath`""

Write-Host "Launching as '$UserName' in $RepoPath ..." -ForegroundColor Green
Write-Host "(runas will prompt for the '$UserName' password.)" -ForegroundColor DarkGray

runas /user:$UserName $inner

if ($LASTEXITCODE -ne 0) {
    Write-Warning "runas returned exit code $LASTEXITCODE (wrong password, or the account lacks interactive logon)."
    Write-Host "Verify setup with: .\Check-ClaudeSandbox.ps1" -ForegroundColor Yellow
}
else {
    Write-Host "Launched. In the new window, run: claude" -ForegroundColor Cyan
}
