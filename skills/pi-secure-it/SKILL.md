---
name: pi-secure-it
description: Use this skill when the user asks about the pi-secure-it extension, security policy configuration, why a tool call was blocked, how to add an allow-list entry, or how to configure sandbox behavior. Covers the two-layer sandbox (OS-level bash sandbox and in-process tool guard), policy file locations and fields, ask-tier prompt options, absolute-deny paths, escape hatches (--yolo, --no-sandbox), the audit log, and common tasks like allowing a new domain or write path.
---

# Pi Security — Skill

Use this skill when the user asks about the pi-secure-it extension, security policy configuration, why a tool call was blocked, how to add an allow-list entry, or how to configure sandbox behavior.

## What this extension does

**Layer 1 — Bash sandbox (OS-level)**
Wraps the `bash` tool with `sandbox-exec` (macOS) or `bubblewrap` (Linux). Blocks:
- Filesystem writes outside `allowWrite`
- Filesystem reads of `denyRead` paths
- Network egress to domains not in `allowedDomains`

**Layer 2 — In-process tool guard**
Hooks `tool_call` for `read`, `grep`, `find`, `ls`, `write`, `edit`, `fetch_content`, `web_search`, `get_search_content`. Applies the same policy file as Layer 1. For `grep`, `find` and `ls` the search root is checked like a `read` path. A `tool_result` hook also removes `grep` output lines from denied files beneath an allowed root (for example a `.env` deep in the tree); approving the root does not approve those files. When a call is blocked, shows an interactive prompt with persistence options.

**Layer 3 — Subagent posture**
When `ctx.hasUI === false` (subagents, `-p`, JSON mode), applies the `subagent.network` policy: `allow` (default) | `deny` | `research-only`.

## Policy files

Merged in order (later wins):
1. `~/.pi/agent/extensions/sandbox.json` — global user policy
2. `<cwd>/.pi/sandbox.json` — project-local overrides (also written by ask-tier prompts)

## Key policy fields

```jsonc
{
  "enabled": true,
  "network": {
    "allowedDomains": ["github.com", "*.github.com"],  // empty = allow all
    "deniedDomains": []
  },
  "filesystem": {
    "denyRead": ["~/.ssh"],           // Layer 1 + 2: hard block
    "modelDenyRead": ["~/.netrc"],    // Layer 2 only: model read blocked, subprocesses ok
    "allowWrite": [".", "/tmp"],      // Layer 2: write only inside these
    "denyWrite": [".env", "*.pem"]   // Layer 1 + 2: always blocked
  },
  "subagent": { "network": "allow" },
  "overrides": {                      // written by ask-tier prompts or manual edits
    "allowRead": [],
    "allowWrite": [],
    "allowDomains": []
  }
}
```

## Absolute-deny tier

Paths matching `~/.ssh`, `~/.gnupg`, `~/.aws`, `*.pem`, `*.key` and pi's own `~/.pi/agent/auth.json` are always high-risk blocks. To allow one call the user picks *allow this ONE call* in a menu that defaults to block, then *Yes* in a second menu that also defaults to No. Enter-Enter blocks. In headless mode these calls are always blocked. The "always" option is never available for these paths.

## Layer 2 role: guard or floor

`layer2` in `sandbox.json` is `"guard"` or `"floor"`; unset means floor when @gotgenes/pi-permission-system is active for the session, else guard. In floor mode pi-permission-system decides and prompts for paths; Layer 2 only enforces the absolute-deny tier, filters grep output from denied files, and blocks web domains outside `network.allowedDomains` without prompting. `/security` shows the active role. If a user sees no Layer 2 prompt for a `denyRead` path, check whether floor mode is active and point them at pi-permission-system's `path` rules.

## Ask-tier prompt options

When a normal (non-absolute-deny) call is blocked in guard mode:
- **no — block** — hard deny (default, pre-selected)
- **yes — this once** — allow just this call
- **yes — for this session** — this file, its parent folder, or this domain until the session ends; not saved
- **always for CURRENT project** — whitelist this file in `<cwd>/.pi/sandbox.json`
- **always for CURRENT project (folder)** — whitelist the parent directory
- **always for ALL projects** — whitelist in `~/.pi/agent/extensions/sandbox.json`
- **always for ALL projects (folder)** — whitelist parent directory globally

## Commands

- `/security` — show Layer 2 status, effective policy, and last 10 audit events
- `/sandbox` — show Layer 1 bash sandbox config
- `/sandbox reload` — live-reload sandbox after manual `sandbox.json` edits

## Escape hatches

```bash
pi --yolo          # disables ALL layers
pi --no-sandbox    # alias for --yolo
```
Setting `"enabled": false` in `sandbox.json` disables Layer 2 without disabling Layer 1.

## When a policy file does not parse

`sandbox.json` is strict JSON. One trailing comma makes both layers skip the whole file and fall back to the built-in defaults. Layer 2 reports this at session start ("does not parse, so neither layer applies its rules") and writes `policy-parse-error` to the audit log. If a user reports that their rules have no effect, check this first: `node -e 'JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"))' <file>`. The "always" prompts refuse to write to an unparseable file.

## Audit log

`~/.pi/agent/audit.log` — append-only JSONL, one entry per decision.

## Common tasks

**Allow a new domain** — either answer "always" in the prompt when the block fires, or add it manually:
```json
// ~/.pi/agent/extensions/sandbox.json  (global)
// or <cwd>/.pi/sandbox.json  (project-local)
{ "overrides": { "allowDomains": ["api.example.com"] } }
```

**Allow writes to a new path** — same pattern with `allowWrite`.

**View recent blocks** — run `/security` and read the audit section, or:
```bash
tail -20 ~/.pi/agent/audit.log | python3 -m json.tool
```

**Disable for one session** — `pi --yolo` or `pi --no-sandbox`.
