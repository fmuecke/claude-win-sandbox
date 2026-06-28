# claude-win-sandbox

Run Claude Code on Windows as a dedicated low-privilege local user, inside a
Visual Studio Developer Shell, scoped to a fixed workspace directory.

This is blast-radius reduction for Windows-native development. It is not hard
containment. Use a VM for adversarial code or strong isolation.

## Requirements

- Windows 10/11
- Visual Studio installed machine-wide
- Git for Windows installed machine-wide
- Admin rights for setup, removal, and policy installation

## Setup

Run once from an elevated PowerShell:

```powershell
.\Setup-ClaudeSandbox.ps1
```

Install the Claude Code managed settings, also elevated:

```powershell
New-Item -ItemType Directory -Path C:\ProgramData\ClaudeCode -Force | Out-Null
Copy-Item .\managed-settings.json C:\ProgramData\ClaudeCode\ -Force
$f = 'C:\ProgramData\ClaudeCode\managed-settings.json'
icacls $f /inheritance:r /grant 'Administrators:F' 'SYSTEM:F' 'Users:R'
```

Start the sandbox shell:

```powershell
.\Start-ClaudeSandbox.ps1
```

In the new window, install Claude Code as the `ClaudeSandbox` user:

```powershell
irm https://claude.ai/install.ps1 | iex
```

Close and reopen the sandbox shell, then verify from an elevated PowerShell:

```powershell
.\Check-ClaudeSandbox.ps1
```

## Daily Use

```powershell
.\Start-ClaudeSandbox.ps1
```

Enter the `ClaudeSandbox` password when `runas` prompts. In the new window:

```powershell
claude
```

## Removal

Run from an elevated PowerShell:

```powershell
.\Remove-ClaudeSandbox.ps1
```

Removal deletes the sandbox user, profile, generated ProgramData state, firewall
rules, and optional desktop shortcut. It does not delete the workspace directory,
for example `C:\dev\ClaudeSandbox`.

## Notes

- Claude Code must be installed per-user under `C:\Users\ClaudeSandbox`, not
  machine-wide and not from your main profile.
- Trusted bootstrap/config files live under ProgramData and are locked
  admin-write / Users-read-execute.
- The sandbox user can still access anything explicitly placed in the sandbox
  workspace and anything otherwise readable by normal Windows users.
- HTTPS/web egress remains available for Claude Code, git, package managers, and
  internal services.

## More Detail

- [Extended guide](docs/extended.md)
- [Threat model](docs/threat-model.md)
- [Codex Windows sandbox notes](docs/codex-sandbox.md)

## License

[MIT](LICENSE)
