# pi-permissions

Claude Code-style permission modes for [pi](https://www.npmjs.com/package/@mariozechner/pi-coding-agent). Controls when the agent needs approval for file writes, edits, and bash commands.

## Installation

```bash
pi install npm:@rhedbull/pi-permissions
```

Or from git:

```bash
pi install git:github.com/rhedbull/pi-permissions
```

## Permission Modes

| Mode | Status | Write/Edit | Normal Bash | Dangerous Bash | Catastrophic |
|------|--------|-----------|-------------|----------------|--------------|
| `default` | `⏵ Default` | ❓ Confirm | ❓ Confirm | ❓ Confirm | 🚫 Blocked |
| `acceptEdits` | `⏵⏵ Accept Edits` | ✅ Auto | ❓ Confirm | ❓ Confirm | 🚫 Blocked |
| `fullAuto` | `⏵⏵⏵ Full Auto` | ✅ Auto | ✅ Auto | ❓ Confirm | 🚫 Blocked |
| `bypassPermissions` | `⏵⏵⏵⏵ Bypass Permissions` | ✅ Auto | ✅ Auto | ✅ Auto | 🚫 Blocked |

### Approval Options

When prompted for confirmation, you can:

- **Allow once** — approve this specific call only
- **Allow for session** — auto-approve this tool (or exact bash command) for the rest of the session
- **Deny** — block the operation

## CLI Flags

```bash
pi --default              # Confirm everything
pi --accept-edits         # Auto-approve file edits
pi --full-auto            # Auto-approve safe bash too
pi --bypass-permissions   # Allow everything (except catastrophic)
```

## Commands

| Command | Description |
|---------|-------------|
| `/permissions` | Interactive mode selector |
| `/permissions <mode>` | Set mode directly (tab-completion supported) |
| `/permissions:status` | Show current mode and session approvals |

## Keyboard Shortcut

**Ctrl+Shift+P** — Cycle through permission modes

## Catastrophic Command Protection

These commands are **always blocked** in every mode, including `bypassPermissions`. They cannot be overridden:

- `sudo rm -rf /`, `rm -rf /`, `rm -rf /*`
- `mkfs.*`, `dd if=`, `sudo dd`
- `:(){ :|:& };:` (fork bomb)
- `sudo chmod -R 777 /`, `sudo chown -R`
- `> /dev/sda`, `> /dev/nvme`

## Protected Path Enforcement

Writes and edits to sensitive paths are **always blocked** in every mode:

- `~/.ssh` — SSH keys, authorized_keys, config
- `~/.aws` — AWS credentials
- `~/.gnupg`, `~/.gpg` — GPG keys
- `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.zshrc`, `~/.zprofile` — Shell startup files
- `~/.config/git/credentials` — Git credentials
- `~/.netrc` — Network credentials
- `~/.npmrc` — npm auth tokens
- `~/.docker/config.json` — Docker registry auth
- `~/.kube/config` — Kubernetes cluster access
- `~/.pi/agent/auth.json` — Pi API keys

This covers both direct `write`/`edit` tool calls and bash commands referencing these paths.

## Configuration

Configuration is loaded from two optional JSON files, merged in order (project overrides global):

- **Global**: `~/.pi/agent/extensions/permissions.json`
- **Project**: `.pi/extensions/permissions.json`

### Example Configuration

```json
{
  "mode": "acceptEdits",
  "dangerousPatterns": [
    { "pattern": "rm -rf", "description": "recursive force delete" },
    { "pattern": "docker system prune", "description": "docker cleanup" }
  ],
  "catastrophicPatterns": [
    { "pattern": "sudo rm -rf /", "description": "sudo recursive delete root" }
  ],
  "protectedPaths": [
    "~/.ssh",
    "~/.aws",
    "/etc/passwd"
  ]
}
```

### Configuration Fields

| Field | Default | Description |
|-------|---------|-------------|
| `mode` | `"acceptEdits"` | Default permission mode |
| `dangerousPatterns` | See defaults | Commands requiring confirmation in fullAuto |
| `catastrophicPatterns` | See defaults | Commands always blocked, all modes |
| `protectedPaths` | See defaults | Paths where writes are always blocked |

## Works With

Designed to work alongside [`@aliou/pi-guardrails`](https://www.npmjs.com/package/@aliou/pi-guardrails). Guardrails handles `.env` file protection and AST-based dangerous command detection, while this extension handles the broader permission mode workflow.
