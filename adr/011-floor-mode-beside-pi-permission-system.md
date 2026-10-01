# ADR-011: Floor mode beside @gotgenes/pi-permission-system

**Status:** Accepted

## Context

`@gotgenes/pi-permission-system` is a mature decision layer for pi: allow/deny/ask rules for paths (with read/write direction and an `external_directory` boundary), bash parsed with tree-sitter, MCP and skills, session grants, subagent prompt forwarding, project-trust gating and an authorizer chain. It explicitly does not sandbox ("it decides and records; a sandbox contains"). Checked against its 36.2.1 source, three things pi-secure-it does are not covered there:

- it hooks only `tool_call`, so a grep over an allowed root still returns lines from denied files beneath it (`.env` under `.`);
- web tools such as `fetch_content` are gated by tool name only, with no domain allowlist;
- there is no built-in credential floor; protection of `.env`, `~/.ssh` and the like depends on the user's rules.

Running both extensions with Layer 2 prompting would ask twice for the same call.

## Decision

`layer2: "guard" | "floor"` in `sandbox.json`.

- **guard** (unchanged behaviour): Layer 2 decides every policy miss and prompts.
- **floor**: Layer 2 leaves path decisions to pi-permission-system and never prompts for them. It keeps:
  - the absolute-deny tier (two-step menu, blocked headless);
  - the grep output filter (ADR-008), driven by `denyRead`, `modelDenyRead` and the absolute-deny tier;
  - the domain allowlist for web tools: an unlisted domain is blocked without a prompt, with a reason naming `network.allowedDomains`.
- **Unset**: `floor` when pi-permission-system has published a service for the current session (`globalThis[Symbol.for("@gotgenes/pi-permission-system:session-services")]`), otherwise `guard`. Detected per call, so load order does not matter.

Layer 1 (OS sandbox for bash) is unaffected by either role.

## Consequences

- One decision layer prompts; pi-secure-it contributes what it uniquely covers.
- In floor mode, `denyRead` and `modelDenyRead` still drive the grep filter and Layer 1, but a direct `read` of such a path is pi-permission-system's call. Users who rely on `modelDenyRead` should mirror those paths as `path` deny rules there.
- The detection relies on pi-permission-system's published `Symbol.for` key; if it changes, Layer 2 falls back to `guard` (more prompting, never less).
