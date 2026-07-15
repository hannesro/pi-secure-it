# ADR-005: Subagent posture — filesystem fail-closed, network opt-in

**Status:** Accepted

## Context

Subagents and scripted runs (`pi -p`, JSON mode) have `ctx.hasUI === false`. They cannot show a prompt. The question is whether they should be more or less restricted than an interactive session.

There are two separate surfaces:
- **Filesystem** — deny rules protect credentials and system files regardless of context.
- **Network** — subagents often need to fetch URLs (research agents, librarian, scout). Blocking by default would break these workflows.

The `ctx.hasUI === false` detector is imprecise: it also catches legitimate scripted runs that are not subagents.

## Decision

- **Filesystem:** deny rules (`denyRead`, `modelDenyRead`, `denyWrite`, `allowWrite`) apply identically in all contexts. No prompts; hard block.
- **Network:** controlled by `subagent.network` in `sandbox.json`, defaulting to `"allow"`:
  - `"allow"` — no change (default, avoids breaking scripted runs)
  - `"deny"` — block all network tool calls in headless contexts
  - `"research-only"` — allow only if the session transcript contains a known research-agent name (best-effort heuristic; not a security boundary)

## Consequences

- Credential protection is unconditional — no subagent can read `~/.ssh` or write outside `allowWrite`, ever.
- Network is opt-in restrictive. Users who want tighter subagent network control set `subagent.network = "deny"` explicitly.
- `"research-only"` is a UX convenience, not a security boundary. A future version should plumb agent identity through `ctx`.
