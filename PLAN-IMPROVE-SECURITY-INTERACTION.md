# PLAN: Improve Security Interaction (Interactive Sandbox Prompts)

**Status:** proposed
**Created:** 2026-04-27
**Owner:** hhr1fe
**Related:** `extensions/` (current `sandbox.json`), `SECURITY_PLAN.md`, `SECURITY.md`

## Problem

Current sandbox (`~/.pi/agent/extensions/sandbox.json`) is a hard allow/deny
list. When the model hits a path outside `allowWrite` it fails silently from
the user's perspective — the agent reports "blocked", and the user has to:

1. Stop the session
2. Hand-edit `sandbox.json`
3. Restart pi
4. Resume

This happened concretely while trying to write a note into
`~/apps/obsidian/vaults/work/Notes/`. Yolo mode does not help because yolo is
L1 (prompt auto-approval), while the block is L2 (in-process policy).

The friction pushes toward over-broad whitelists ("just add the whole vault")
which defeats the purpose of having a tight policy in the first place.

## Goal

Replace the static-config UX with an **interactive prompt on block**, while
keeping the same hardened defaults and self-protection guarantees. Specifically:

- On block, prompt the user with: Abort / Allow this session / Allow this
  project / Allow all projects.
- "Session" allowances live in memory only and are unreadable/unwritable by
  the agent.
- "Project" writes to `.pi/sandbox.json` (per-repo policy).
- "All projects" writes to `~/.pi/agent/sandbox.json`.
- `denyWrite` always wins, even if a path is granted via prompt — show a
  warning explaining which file to edit.

## Reference implementation

[`carderne/pi-sandbox`](https://github.com/carderne/pi-sandbox) — a fork of
the same Mario Zechner example our current `sandbox.json` derives from. Adds
the prompt UX, per-project config, and a footer lock indicator.

- 902 lines of TS in a single `index.ts`
- One prod dep: `@carderne/sandbox-runtime` (fork of
  `anthropic-experimental/sandbox-runtime`, used for L1 bash via
  `sandbox-exec` on macOS / `bubblewrap` on Linux)
- MIT, npm provenance enabled, single maintainer

## Why we are NOT just `pi install npm:pi-sandbox`

Pi extensions run in-process with full Node privileges. The sandbox
extension is the *most* privileged thing in pi — it's what gates everything
else. A compromised update would have unrestricted access to read/write/exec
on the host before any policy could stop it.

Specific risks:

- **Single maintainer** for both the extension and its main dependency
  (`@carderne/sandbox-runtime`). Single point of account/key compromise.
- **Forked dependency**: `@carderne/sandbox-runtime` diverges from Anthropic's
  upstream — we'd be trusting one person's patches to security-critical code.
- **npm provenance** mitigates supply-chain tampering on publish but not
  account compromise or malicious-by-author updates.
- **Auto-update via `pi install`** means a future malicious version lands
  silently unless we pin + lock.

We already maintain `~/.pi/pi-security-workspace/` as a source-of-truth repo
specifically so security-critical pieces are versioned, auditable, and
self-protected (`denyWrite: ~/.pi/agent/extensions/**`). The right move is to
fold this code into that repo, not to add an external dependency to it.

## Plan

### Phase 1 — Audit (½ day)

- [ ] Read `carderne/pi-sandbox/index.ts` end-to-end (902 LOC, feasible).
- [ ] Read `@carderne/sandbox-runtime` source — note divergence from Anthropic
      upstream. Decide whether to vendor it too or pin-and-watch.
- [ ] Diff `carderne/pi-sandbox`'s default config against our current
      `sandbox.json` — list every behavioural delta (read semantics,
      `allowBrowserProcess`, `allowLocalBinding`, `allowAllUnixSockets`, etc.)
      so nothing regresses silently.
- [ ] Confirm the prompt mechanism cannot be triggered/auto-answered by the
      model itself (must be a real human-input gate, not a tool call).

### Phase 2 — Vendor (½ day)

- [ ] Create `extensions/sandbox/` in `pi-security-workspace`:
  - `index.ts` — copied from upstream, header comment with source commit hash
        and date.
  - `package.json` — local, with `@carderne/sandbox-runtime` pinned to an
        **exact** version + integrity hash in lockfile.
  - `README.md` — what it is, why we vendored, how to update.
- [ ] Add `extensions/sandbox/**` to `denyWrite` (self-protection, same as
      current `~/.pi/agent/extensions/**` rule).
- [ ] Point pi at the local extension instead of npm. Document the install
      command in the README.
- [ ] Migrate our current `sandbox.json` content into the new defaults. Keep
      the existing tight `allowWrite` list — the prompt UX is the relaxation
      mechanism, not a wider default.

### Phase 3 — Validate (½ day)

- [ ] Trigger a write to a non-allowed path (the original obsidian vault
      case). Verify the prompt appears and that "Allow all projects" persists
      to `~/.pi/agent/sandbox.json` correctly.
- [ ] Verify `denyWrite` precedence: try to grant a path that's also in
      `denyWrite`, confirm hard block + warning.
- [ ] Verify session allowances do not survive a pi restart and are not
      visible to the agent (`bash` and model `read` both fail to find them).
- [ ] Verify L1 bash sandbox still works (`bash` write to non-allowed path
      blocks at OS level, not just L2).
- [ ] Verify yolo does NOT auto-answer the new prompts.

### Phase 4 — Update workflow

- [ ] Document in repo README: how to pull upstream changes
      (`git diff` upstream `index.ts` against vendored copy, review, merge,
      bump dep with new integrity hash).
- [ ] Optional: GitHub Action that opens a PR when upstream
      `carderne/pi-sandbox` releases a new version, with a diff summary —
      review-then-merge, never auto-merge.

## Open questions

- Vendor `@carderne/sandbox-runtime` too, or pin + watch? Vendoring means
  also tracking Anthropic's upstream when it moves. Pinning means trusting
  one person's npm account indefinitely. **Lean: pin + watch initially,
  vendor if it gets sketchy.**
- Where should per-project `.pi/sandbox.json` files live in our workflows?
  Should they be committed to project repos (visible policy) or gitignored
  (local preference)? **Lean: commit, with `denyWrite` rules also enforced
  globally so a malicious project repo can't widen.**
- Does the upstream extension allow a project-local config to *widen* a
  global `denyWrite`? If yes, we need to patch that out — global denies
  must always win.

## Non-goals

- Replacing the L1 bash sandbox (`sandbox-exec` / `bubblewrap`). Keep using
  whichever runtime we end up with; this plan is about the L2 UX.
- Building our own prompt UI from scratch. The upstream code already does
  this well; our contribution is the audit + vendoring + self-protection.

## Success criteria

- Hitting a blocked path produces a prompt, not a session-stopping error.
- Granting "all projects" persists correctly and survives restart.
- All security-critical files (`extensions/sandbox/**`, `sandbox.json`) are
  in `denyWrite` and cannot be modified by the agent.
- No regression vs. current policy: every path currently blocked is still
  blocked unless explicitly granted via prompt.
- Update process for upstream changes is documented and requires human
  review of every diff.
