# ADR-003: Ask-tier interactive prompts instead of silent blocks

**Status:** Accepted

## Context

The original sandbox was a hard allow/deny list. When the model hit a path outside `allowWrite` it failed silently from the user's perspective — the agent reported "blocked" and the user had to stop, hand-edit `sandbox.json`, and restart. This happened concretely when trying to write into `~/apps/obsidian/vaults/work/`. The friction pushed toward over-broad whitelists ("just add the whole vault") which defeats the purpose of a tight policy.

## Decision

When a block fires in interactive mode (`ctx.hasUI === true`), show a prompt with four persistence tiers instead of silently failing:

1. **yes — this once** — allow the call, no policy change
2. **no — block** — hard deny, default on timeout/Esc
3. **always for CURRENT project** — write `<cwd>/.pi/sandbox.json` (file or parent-folder granularity)
4. **always for ALL projects** — write `~/.pi/agent/extensions/sandbox.json` (file or parent-folder granularity)

In headless contexts (`ctx.hasUI === false`: `-p` mode, JSON mode, subagents) the prompt is skipped and the call is hard-blocked — no exceptions.

Every decision (yes / no / always-*) is appended to `~/.pi/agent/audit.log`.

## Consequences

- Users can grant access without leaving pi.
- Granular granularity (file vs. parent folder) avoids over-broad whitelists.
- **Rejected alternative:** "retry once without sandbox" (pi-sandbox upstream pattern). Rejected because a retry silently runs the blocked code — the user never sees what was attempted. An explicit allow decision is safer and auditable.
- **Rejected alternative:** never-persist "always" from a prompt (only manual edits). Rejected because the friction was the original problem.
