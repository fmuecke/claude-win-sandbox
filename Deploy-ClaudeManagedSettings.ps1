#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Deploys an enterprise managed-settings.json for Claude Code and locks it so
    only Administrators can modify it. This is the agent-level belt ON TOP of
    your OS ACLs - it is NOT a security boundary on its own (see notes).

.IMPORTANT
    - Managed settings take highest precedence and cannot be overridden by the
      user's ~/.claude/settings.json or a project .claude/settings.json.
    - Deny rules here gate Claude Code's Read/Edit/WebFetch tools. They DO NOT
      stop a Bash command (cat / Get-Content / diff) from reading a file - that
      is governed by the Bash permission, and content still enters context.
      => Your NTFS ACLs from Setup-ClaudeUser.ps1 remain the real enforcement.
    - Keep Claude Code UPDATED. Several permission-bypass CVEs have been patched.
#>

[CmdletBinding()]
param(
    [string]$ManagedDir = 'C:\ProgramData\ClaudeCode'
)

$ErrorActionPreference = 'Stop'
$managedFile = Join-Path $ManagedDir 'managed-settings.json'

# --- The policy ---------------------------------------------------------------
# defaultMode "default": prompt on first use of each tool (no silent bypass).
# disableBypassPermissionsMode: ClaudeSandbox CANNOT use --dangerously-skip-permissions.
# deny: block the obvious secret reads at the agent layer (belt, not boundary).
# allow: pre-approve the routine git + build verbs so the session is usable.
$settings = @'
{
  "permissions": {
    "defaultMode": "default",
    "deny": [
      "Read(**/.ssh/**)",
      "Read(**/.aws/**)",
      "Read(**/.azure/**)",
      "Read(**/.git-credentials)",
      "Read(**/_netrc)",
      "Read(**/*.pat)",
      "Read(**/*.kdbx)",
      "Read(**/secrets/**)",
      "Read(**/.env)",
      "Read(**/.env.*)",
      "Bash(cat *id_rsa*)",
      "Bash(cat *.kdbx*)",
      "Bash(Get-Content *id_rsa*)",
      "Bash(Get-Content *.kdbx*)",
      "Bash(reg query *Credential*)",
      "Bash(cmdkey *)",
      "WebFetch"
    ],
    "ask": [
      "Bash(git push *)",
      "Bash(git remote *)"
    ],
    "allow": [
      "Bash(git status *)",
      "Bash(git diff *)",
      "Bash(git add *)",
      "Bash(git commit *)",
      "Bash(git log *)",
      "Bash(git fetch *)",
      "Bash(git pull *)",
      "Bash(git checkout *)",
      "Bash(git branch *)",
      "Bash(msbuild *)",
      "Bash(cl *)",
      "Bash(cmake *)",
      "Bash(ctest *)",
      "Bash(dir *)",
      "Read(C:/dev/repo/**)",
      "Edit(C:/dev/repo/**)"
    ]
  },
  "disableBypassPermissionsMode": "disable"
}
'@

# --- Deploy -------------------------------------------------------------------
if (-not (Test-Path $ManagedDir)) {
    New-Item -ItemType Directory -Path $ManagedDir -Force | Out-Null
}
Set-Content -Path $managedFile -Value $settings -Encoding UTF8
Write-Host "Wrote $managedFile" -ForegroundColor Green

# --- Lock it: only Administrators + SYSTEM may modify; Users read-only --------
# Break inheritance, then set an explicit DACL.
icacls $managedFile /inheritance:r | Out-Null
icacls $managedFile /grant "Administrators:F" | Out-Null
icacls $managedFile /grant "SYSTEM:F"          | Out-Null
icacls $managedFile /grant "Users:R"           | Out-Null
Write-Host "Locked: Administrators/SYSTEM = Full, Users = Read-only" -ForegroundColor Green

Write-Host @"

Managed policy deployed. Verify from a ClaudeSandbox session with:
    claude   ->  /permissions      (should show rules sourced from managed-settings)

Reminders:
  - This layer is defense-in-depth, NOT a boundary. NTFS ACLs do the real work.
  - Bash can still technically read files the OS lets ClaudeSandbox read; the
    deny globs above only catch obvious patterns. Rely on ACLs for secrets.
  - Keep Claude Code updated (permission-bypass CVEs have been fixed over time).
  - 'WebFetch' is denied wholesale to close the prompt-injection exfil path.
    Remove it from deny if ClaudeSandbox legitimately needs web fetch.
"@ -ForegroundColor Cyan
