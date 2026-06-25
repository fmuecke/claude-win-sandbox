# claude-win-sandbox

Run **Claude Code** on Windows under a dedicated low-privilege user, inside a
Visual Studio Developer Shell, scoped to a single project directory — **without
Docker and without WSL.**

This fills a gap: existing Claude Code sandboxing projects are all Docker- or
WSL/bubblewrap-based. None of them work for the **Windows-native + MSVC + on-prem
toolchain** stack common in embedded, automotive, industrial, and enterprise C++
shops. This project is for that case.

> **Threat model:** This is **blast-radius reduction**, not hard containment.
> It defends against agent mistakes and prompt-injection overreach on a machine
> you basically trust. It is **not** a security boundary against a determined
> attacker who already has your privileges. For hard isolation, use a VM. See
> [Limitations](#limitations).


## What it does

1. **`Setup-ClaudeSandbox.ps1`** (run once, elevated)
   - Creates a low-privilege local user (`ClaudeSandbox`) if absent
   - Hardens it: denies network + RDP logon, password never-expires /
     user-cannot-change, hidden from the login screen. **Interactive logon is
     left enabled on purpose** — the launcher uses it; denying it breaks launch.
   - Grants it Modify on `C:\dev\repo` (shared with you; sub-repos beneath it
     are covered via inheritance)
   - Verifies your profile isn't readable by Users/Everyone (a Standard user is
     denied your profile by default — the script warns if yours is misconfigured)
   - Locates VS Developer Shell + git, writes a Dev Shell bootstrap

2. **`managed-settings.json`** (copy once, elevated)
   - Enterprise Claude Code policy: denies obvious secret reads, disables
     bypass-permissions mode, pre-approves routine git + build verbs
   - Copy to `C:\ProgramData\ClaudeCode\` and lock it (see setup below)

3. **`Start-ClaudeSandbox.ps1`** (run per session, normal priv)
   - Prompts for the `ClaudeSandbox` password (via `runas`)
   - Launches a new console as `ClaudeSandbox`, in the Dev Shell, `cd`'d to
     `C:\dev\repo` (override with `-RepoPath`)
   - You type `claude` and go

4. **`Check-ClaudeSandbox.ps1`** (run anytime, read-only)
   - Verifies the whole setup: user exists & is non-admin, hardening applied,
     repo ACLs, your profile isn't exposed, bootstrap + toolchain present, policy
     file valid and admin-locked
   - Prints PASS/WARN/FAIL; exits non-zero on any FAIL. Run elevated for full
     coverage (user-rights + HKLM checks). Doubles as a post-launch diagnostic.


## Why a separate user (and not just sandbox flags)

Claude Code runs with **your** OS privileges by default — it can read anything
you can: env vars, SSH keys, PATs, credential stores. On Windows, Anthropic's
native bubblewrap sandbox **isn't available yet** (WSL2/Linux/macOS only). So on
native Windows the most practical OS-level boundary is a **separate low-priv
user**: the NTFS ACLs do the enforcing, and Claude Code physically can't reach
what that user can't reach.

This pairs with — doesn't replace — Claude Code's own permission system and the
managed-settings deny rules. Defense in depth:

| Layer | What it stops | Enforced by |
|-------|---------------|-------------|
| NTFS ACLs (low-priv user) | Reading/writing your secrets & system dirs | Windows kernel |
| `managed-settings.json` deny rules | Agent tool calls to secret paths | Claude Code |
| Permission prompts (no bypass mode) | Unreviewed command execution | Claude Code |
| Network separation (your env) | Exfiltration | Your network |


## Prerequisites

- Windows 10/11, dedicated/trusted dev machine
- Visual Studio (Pro or higher) installed machine-wide
- Git for Windows installed machine-wide
- Claude Code installed (per-user under `ClaudeSandbox`, or machine-wide)
- Admin rights for the two setup scripts


## Setup

```powershell
# 1. Provision the user, ACLs, bootstrap  (ELEVATED)
.\Setup-ClaudeSandbox.ps1

# 2. Install the Claude Code policy  (ELEVATED)
New-Item -ItemType Directory -Path C:\ProgramData\ClaudeCode -Force | Out-Null
Copy-Item .\managed-settings.json C:\ProgramData\ClaudeCode\ -Force
$f = 'C:\ProgramData\ClaudeCode\managed-settings.json'
icacls $f /inheritance:r /grant 'Administrators:F' 'SYSTEM:F' 'Users:R'   # admin-write only

# 2b. Verify everything took  (ELEVATED for full coverage)
.\Check-ClaudeSandbox.ps1

# 3. First-time: log in as ClaudeSandbox once to set up its git/ADO credential
#    (scoped, minimal PAT — kept separate from yours)
```

Then, day to day (normal PowerShell, no elevation):

```powershell
.\Start-ClaudeSandbox.ps1                       # uses C:\dev\repo
.\Start-ClaudeSandbox.ps1 -RepoPath C:\dev\other   # or override
# enter ClaudeSandbox password (runas) -> new window opens -> type: claude
```


## Credential handling

The launcher uses **`runas`**, which prompts for the password each launch and
opens an interactive console as `ClaudeSandbox`. `runas` is used rather than
`Start-Process -Credential` because it attaches the new process to an interactive
desktop — `Start-Process -Credential` can produce a window that renders but won't
accept keyboard input (a "hung" shell).

No password caching: the prompt is the only credential path, which keeps the tool
simple and avoids storing the password anywhere.


## Windows Terminal profile (optional)

Add a profile so it's one click from the dropdown:

```json
{
  "name": "Claude (sandboxed)",
  "commandline": "powershell.exe -NoExit -ExecutionPolicy Bypass -File C:\\dev\\claude-tools\\Start-ClaudeSandbox.ps1",
  "icon": "ms-appx:///ProfileIcons/{0caa0dad-35be-5f56-a8ff-afceeeaa6101}.png",
  "startingDirectory": "C:\\dev\\repo"
}
```

## Limitations

- **The boundary is Windows' default profile ACL**, not explicit deny rules.
  A Standard user can't read your profile on a correctly configured system; the
  setup script verifies this rather than patching over it with brittle deny ACEs.
  Secrets kept *outside* your profile (e.g. a vault under `C:\` or a share) aren't
  covered by that default — protect those paths' ACLs separately.
- **No native bubblewrap on Windows.** When Anthropic ships native Windows
  sandboxing, prefer it (or stack it on top of this).
- **Managed-settings deny rules are defense-in-depth, not airtight.** Claude
  Code has had permission-bypass CVEs (symlink tricks, path resolution). Keep it
  updated.
- **`ClaudeSandbox` needs its own writable profile** for `~/.claude` config — that's
  fine; it contains none of your secrets.
- **Debugging system processes still needs elevation.** Don't run *this* elevated
  to get there. Keep agent autonomy and elevation in separate processes — run
  elevated VS for debugging (agent mode off), agentic AI here (low-priv).

## Why not Docker / WSL?

Both are great and already well-served by other projects — use them if your
workload runs there. This project exists specifically for **native Windows
toolchains** (MSVC, classic .vcxproj, on-prem build) that can't move into a
Linux container without losing the toolchain.

## License

[MIT](LICENSE)

## Status

Personal project. Opinionated, minimal, not affiliated with Anthropic.
```
