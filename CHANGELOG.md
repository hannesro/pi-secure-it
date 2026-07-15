# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2026-07-15

### Added
- **Layer 1** — OS-level bash sandbox via `@anthropic-ai/sandbox-runtime` (`sandbox-exec` on macOS, `bubblewrap` on Linux). Blocks filesystem writes outside `allowWrite`, reads of `denyRead`, and network outside `allowedDomains`.
- **Layer 2** — In-process tool guard hooking `read`, `write`, `edit`, `fetch_content`, `web_search`, `get_search_content`. Applies the same policy file as Layer 1.
- **Layer 3** — Subagent posture: stricter network policy when `ctx.hasUI === false` (subagents, `-p` mode, JSON mode). Configurable via `subagent.network`: `allow` (default) | `deny` | `research-only`.
- **Ask-tier prompts** — Interactive per-call allow/deny dialog with four persistence tiers: this-once, always-for-current-project (file), always-for-current-project (folder), always-for-all-projects (file), always-for-all-projects (folder). Persists to `.pi/sandbox.json` or `~/.pi/agent/extensions/sandbox.json`.
- **Absolute-deny tier** — Credential material (`~/.ssh`, `~/.gnupg`, `~/.aws`, `*.pem`, `*.key`) requires typing `"i understand"` verbatim; "always" is never available for this tier.
- **`/security` command** — Shows active policy, project-local overrides, and last 10 audit events.
- **`/sandbox` command** — Shows current bash sandbox config. `/sandbox reload` live-reloads after manual edits to `sandbox.json`.
- **Audit log** — Append-only JSONL at `~/.pi/agent/audit.log`. One entry per blocked/allowed/always decision.
- **`sandbox.example.json`** — Documented reference config showing all available fields.
- **Skill** — `skills/pi-security/SKILL.md` explains the security model and how to configure it.
