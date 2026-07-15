# Ask-tier UX — implementation status

This is the first concrete cut of the design in
[PLAN-ask-tier-ux.md](./PLAN-ask-tier-ux.md). It covers Layer 2 only.
Layer 1 (bash sandbox) and tests are still TODO.

## Files

| Path | Purpose |
|---|---|
| `/private/tmp/pi-502/security-guard.staged.ts` | Staged Layer 2 source |
| `/private/tmp/pi-502/sandbox-index.staged.ts`  | Staged Layer 1 source |
| `~/.pi/playground/scripts/apply-ask-tier.sh` | One-shot installer for both files (run outside pi) |
| `~/.pi/agent/extensions/security-guard.ts` | Current Layer 2 (replaced by the script) |
| `~/.pi/agent/extensions/sandbox/index.ts` | Current Layer 1 (replaced by the script) |
| `~/.pi/agent/audit.log` | Append-only decision log (created by installer if missing) |
| `<cwd>/.pi/sandbox.json` | Project-local "always-for-this-cwd" overrides (written at runtime by either layer's prompt flow) |

## How to install

```bash
~/.pi/playground/scripts/apply-ask-tier.sh   # outside pi, or via --yolo
```

Then restart pi. `/security` shows the new "Project-local overrides" and a 10-line audit tail.

## What's done (PLAN steps)

- [x] **Step 1** — find the prompt primitive. Resolved: `ctx.ui.select / confirm / input` with `{timeout}`. `ctx.hasUI === false` ⇒ no prompt. (See PLAN OQ#1 update.)
- [x] **Step 2** — tier model. Three tiers shipped:
  - **absolute-deny** (hardcoded patterns: `~/.ssh`, `~/.gnupg`, `~/.aws`, `*.pem`, `*.key`) — prompt requires typing `i understand` exactly; `always` is refused.
  - **default-deny** (everything else that hits `denyRead`/`modelDenyRead`/`denyWrite`/URL-allowlist) — three-state prompt (yes / no / always).
  - **default-allow** — never reaches the gate.
- [x] **Step 3** — Layer 2 prompt path. `tool_call` block sites for `read`, `write`, `edit`, `fetch_content`, `get_search_content` go through `askOrBlock`.
- [x] **Step 4** — project-local persistence. `persistAlways(cwd, kind, value)` writes `<cwd>/.pi/sandbox.json` under a new additive `overrides: { allowRead, allowWrite, allowDomains }` section. Avoids clobbering global arrays during `loadPolicy`'s shallow merge (see PLAN OQ#2).
- [x] **Step 5** — Layer 1 (bash sandbox) prompt path. After `EPERM`/`EACCES` is detected in bash output, the same `<cwd>/.pi/sandbox.json` `overrides` section is written and `SandboxManager.reset()` + `initialize()` reload the OS sandbox live. Shape:
  - Two-state prompt (no "this once" — the failed bash command can't be cleanly re-run mid-flight).
  - `foldOverrides()` merges `overrides.allowWrite` into `filesystem.allowWrite` and `overrides.allowDomains` into `network.allowedDomains` before handing to `SandboxManager`.
  - `overrides.allowRead` is intentionally **not** folded into Layer 1: keeps Layer 2's read overrides from accidentally widening the OS sandbox.
  - Prompt fires *after* the bash tool result resolves so the model still sees the EPERM hint and can decide what to do next (typically: retry the command after the prompt is answered).
- [x] **Step 6** — append-only audit log at `~/.pi/agent/audit.log`. Every yes/no/always (Layer 1 and Layer 2) writes a JSONL line with timestamp, layer, tool, subject, decision, cwd, and (for "always") the override.
- [x] **Step 7** — `/security` extended with project overrides and last 10 audit entries. (`/sandbox` automatically reflects overrides because `loadConfig` folds them in.)

## What's NOT done

- [ ] **Step 8** — automated tests (mocked `ctx.ui`, persistence shape, tier escalation, foldOverrides idempotence).
- [ ] **Step 9** — update `flow.md`, `implementation.md`, `tradeoffs.md`.

## Behavioural notes

- **No-UI** (`ctx.hasUI === false`, i.e. `-p`, JSON mode, subagents) → `askDecision` returns `"no"` immediately and the call hard-blocks. The audit line is still written (decision `no`, no `persisted_to`).
- **Timeout** is 60 s per prompt. `select` returns `undefined` on timeout, `input` returns `undefined`; both map to `no`.
- **Override scope** — overrides match exact canonicalised absolute paths for read/write, and hostnames for URLs. Glob patterns *are* supported (the matcher is reused) so a future hand-edit of `<cwd>/.pi/sandbox.json` can use globs, but the prompt always persists a single concrete path/host.
- **Absolute-deny + always** — defense-in-depth: even if a future code path requested `always` for an absolute-deny match, `askOrBlock` refuses to persist and writes an `always-refused-for-absolute-deny` audit note.
- **Audit log integrity** — protected only by Layer 1 sandbox (the model's bash can theoretically truncate it). Not a security boundary; treat as an investigative aid, not as evidence.

## Threat model deltas vs PLAN

| Concern | Status |
|---|---|
| Prompt fatigue → reflex "always" | Mitigated by v2 carve-outs already in place; this layer adds friction (typing for absolute-deny) where it matters most. |
| Misleading prompt context | Path is canonicalised before display; pattern source is policy-controlled. Newlines in `ctx.ui.select` titles render as separate lines, not terminal escapes. |
| Subagent-prompted, parent unaware | Subagents have `hasUI === false` → never prompted → hard block. Confirmed. |
| User toggles "always" then runs hostile prompt later | Project-local entries persist forever in v1. `/security` now surfaces them on demand. Expiry deferred. |
