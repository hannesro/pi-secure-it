# Pi Security Hardening Plan

> **For current shipped state, see [`SECURITY.md`](./SECURITY.md)** (auto-generated from `security/manifest.json` by `./security/check.sh`). This file is the long-form *intent* / threat model / acceptance criteria. Hand-edited.

Owner: hhr1fe · Status: **Draft / In progress** · Last updated: 2026-04-27

> This file is the **plan**: goal, threat model, layers, status, acceptance.
> For concrete configs and code, see [`docs/security/implementation.md`](docs/security/implementation.md).
> For the *why* behind each choice, see [`docs/security/tradeoffs.md`](docs/security/tradeoffs.md).
> For runnable smoke and regression tests, see [`docs/security/testing.md`](docs/security/testing.md).

---

## Goal

Make pi safe to run on a developer workstation against a (potentially)
prompt-injected or misbehaving model: contain what `bash`, `read`, `write`,
`edit`, and `fetch_content` can do — without breaking normal coding
workflows.

## Threat model

**Trusted:** the user, the OS, the pi runtime, the extensions we install.
**Untrusted:** the model and any content it ingests (files, web pages, tool
output) — it may follow injected instructions.

In scope:

- Exfiltration of secrets (`~/.ssh`, `~/.aws`, `~/.gnupg`, `.env`, cloud creds).
- Destructive filesystem writes outside the project (`rm -rf ~`, dotfiles).
- Unsolicited network calls to attacker-controlled domains.
- Subagents inheriting too-broad permissions from the parent session.
- Pi planting files in shared `/tmp` for other tools to ingest.

Out of scope:

- MCP server isolation — deferred until Layers 1 + 2 are stable.
- Kernel-level escapes from `sandbox-exec` / `bubblewrap`.
- Supply-chain attacks against pi or its dependencies.
- Self-update from within pi — done from a plain terminal instead
  ([why](docs/security/tradeoffs.md#why-we-drop-self-update-inside-pi-option-b)).

## Design principles

1. **Defense in depth.** OS sandbox for `bash`, in-process gate for the
   Node-level tools `bash` can't reach.
2. **Allowlist for network, denylist for filesystem.** Matches developer
   ergonomics and `sandbox-runtime` defaults.
3. **One policy file, two readers.** Layer 1 and Layer 2 read the same
   `sandbox.json` — policy can't drift between layers.
4. **Fail closed in subagents.** No interactive UI ⇒ never prompt, always
   block ambiguous cases.
5. **Secure by default, single escape hatch.** All layers active on every
   `pi` launch. One global `--yolo` flag disables *all* layers and prints
   a visible warning. No per-layer toggles.
6. **Quiet on the happy path, informative on the unhappy path.** When the
   sandbox blocks something, the error tells the model where to write
   instead so it can self-correct without looping.

---

## Layers

### Layer 1 — OS-level sandbox for `bash`

Wraps the `bash` tool in `sandbox-exec` (macOS) / `bubblewrap` (Linux) via
`@anthropic-ai/sandbox-runtime`. Constrains every subprocess `bash` spawns
(curl, npm, python, shell scripts, …).

**Scope:** all bash subprocesses.
**Gaps:** doesn't cover `read`, `write`, `edit`, `fetch_content`, `web_search`,
`chrome_devtools_*` (those are in-process — Layer 2's job).

**Status:** ☑ **complete**. Extension installed, policy authored,
`--yolo` escape hatch wired in, dedicated `/private/tmp/pi-<uid>` +
`TMPDIR` injection live, friendly error hint surfacing on blocked
writes, 19/19 automated smoke tests passing (+1 manual SKIP for the
hint, +1 documented XFAIL for raw-IP egress — see
[`tradeoffs.md`](../docs/security/tradeoffs.md)).

### Layer 2 — In-process guard for Node tools

A custom extension hooks `tool_call` and applies the same policy file to
the tools `sandbox-exec` can't reach: `read`, `write`, `edit`,
`fetch_content`, `web_search`, `get_search_content`.

**Critical correctness rules** (path resolution): canonicalize via
`realpath` before matching, reject paths that escape allowed roots via
symlinks or `..`, case-insensitive globs on macOS, check every entry of
`fetch_content.urls[]`.

**Behavior:** silent block by default; in interactive mode optionally
offer "retry once without sandbox" via `ctx.ui.confirm`. Subagents:
always block, never prompt.

**Status:** ☐ not started.

### Layer 3 — Subagent posture

In-process guard inspects `ctx.hasUI`. When false:

- Confirmation prompts disabled (always block on ambiguity).
- Network disabled unless the subagent's `agent` name is in a small
  research allowlist (`librarian`, `scout`).
- `denyRead`, `denyWrite` apply unchanged.
- `allowWrite` may be narrowed to the worktree if `worktree: true`.

**Status:** ☐ not started (lands with Layer 2).

### Layer 4 — Chrome DevTools gate

`chrome_devtools_*` mutator tools (`navigate_page`, `new_page`,
`evaluate_script`, `click`, `fill`, `upload_file`, `handle_dialog`,
`press_key`, `drag`) require one per-session `ctx.ui.confirm`. Read-only
operations (`take_snapshot`, `screenshot`, `list_*`) stay open. Subagents
always denied. `--allow-browser` flag pre-confirms.

**Status:** ☐ not started.

---

## Initial policy

See [`docs/security/implementation.md` § "Active config"](docs/security/implementation.md#active-config-pi-agent-extensions-sandboxjson)
for the full JSON. Highlights:

- Network: npm / pypi / GitHub / crates.io / go proxy + per-project additions.
- Reads denied: `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh`, `~/.netrc`,
  `~/.kube`, `~/.docker/config.json`. **`/tmp` reads stay open**
  ([why](docs/security/tradeoffs.md#why-we-dont-deny-tmp-reads)).
- Writes allowed: cwd, `/private/tmp/pi-<uid>` (mirrors Claude Code's
  pattern), `~/.pi-tmp` (persistent fallback).
- Writes denied: `.env*`, key/cert files, `~/.pi/agent/**` (scoped to
  protect extensions/config without breaking the playground cwd),
  shell rc files.

Per-project `.pi/sandbox.json` overrides as needed (e.g. corp registry,
project-specific write paths).

---

## Rollout order

1. ☑ Layer 1 install + smoke tests.
2. ☑ Layer 1 polish: dedicated `pi-<uid>` tmp dir, `TMPDIR` env, error hints.
3. ☐ **→ next:** Layer 2 extension + path-resolution tests (incl. symlink escape).
4. ☐ Layer 3 (subagent stricter profile) — folds into Layer 2's extension.
5. ☐ Layer 4 (browser gate).
6. Deferred: MCP sandboxing, unified `~/.pi/security.json` schema.

## Acceptance criteria (whole effort)

- A bare `pi` (no flags) cannot read `~/.ssh/id_rsa` via **any** tool.
- A bare `pi` cannot write outside cwd, `$TMPDIR` (= `/private/tmp/pi-<uid>`),
  or `~/.pi-tmp`.
- A bare `pi` cannot reach `evil.example.com` via `bash`, `fetch_content`,
  or `web_search`.
- Subagents fail-closed; non-research subagents have no network.
- `pi --yolo` disables *all* layers and prints a visible warning banner.
- `/security` (or `/sandbox`) prints the active merged policy and the
  per-layer status.
- Normal workflow (`npm install`, `git push`, project edits, doc search,
  `mktemp` / `tempfile()` / npm cache) is unaffected.

## Risks / things to watch

See [`docs/security/tradeoffs.md` § "Risks we're knowingly accepting"](docs/security/tradeoffs.md#risks-were-knowingly-accepting)
for the full list. Most likely to bite us:

- Path canonicalization bugs in Layer 2 (must include the symlink-escape test).
- Tools that hardcode `/tmp` and ignore `$TMPDIR` (we mitigate with a
  helpful error message, not by widening the sandbox).
- `fetch_content` redirects bypass the URL allowlist — documented as a
  v1 limitation.

## Changelog

- 2026-04-27: Layer 2 (in-process guard) shipped at
  `~/.pi/agent/extensions/security-guard.ts`. Layer 3 (subagent posture)
  shipped behind `policy.subagent.network`. 26 unit tests for the path
  matcher, URL allowlist, and symlink-escape defense passing. Plan now
  has Layer 4 (browser gate) as the only remaining work.
- 2026-04-27: implemented `--yolo` flag in `sandbox/index.ts`. Disables
  Layer 1 today; will short-circuit Layers 2–4 once they ship. Kept
  `--no-sandbox` as a hidden alias.
- 2026-04-27: added `docs/security/testing.md` with a Layer-by-Layer
  test matrix and a runnable `run-tests.sh`.
- 2026-04-27: split implementation details and tradeoffs into
  `docs/security/`. Plan is now intent-only.
- 2026-04-27: dedicated `/private/tmp/pi-<uid>` + `TMPDIR` env, decided
  not to denyRead `/tmp` (matches Claude Code & opencode). Scoped
  `denyWrite ~/.pi/**` down to `~/.pi/agent/**` so the playground cwd
  stays writable.
- 2026-04-27: secure-by-default; replaced per-layer flags
  (`--no-sandbox`) with single global `--yolo` escape hatch.
- 2026-04-27: initial draft, scoped to Layers 1–4 with MCP deferred.
