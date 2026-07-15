# Pi Security — Design Tradeoffs

The "why" behind the choices in [`../../SECURITY_PLAN.md`](../../SECURITY_PLAN.md).
For the "how", see [`implementation.md`](./implementation.md).

Last updated: 2026-04-27

---

## Reference points

We use the same OS sandbox primitive as Claude Code
(`@anthropic-ai/sandbox-runtime` → `sandbox-exec` on macOS, `bubblewrap` on
Linux). Where we deviate from Claude Code or opencode, it's deliberate and
documented below.

| Concern | Claude Code | opencode | **pi (this plan)** |
|---|---|---|---|
| OS sandbox for bash | yes (sandbox-exec) | partial | yes — same lib |
| Default `/tmp` write | dedicated `/tmp/claude-<uid>/` + `TMPDIR` | prompts (default-allow proposed) | **dedicated `/private/tmp/pi-<uid>/` + `TMPDIR`** |
| `/tmp` reads | not denied | not denied | **not denied** (see below) |
| Permission tiers | allow / ask / deny | allow / ask / deny | **absolute-deny / default-deny / default-allow**, three-state ask-tier prompt with project-local persistence |
| In-process tools (`read`/`write`/`edit`) | gated separately from bash sandbox | gated | **gated by Layer 2** + ask-tier prompt |
| Subagent posture | inherits | inherits | **stricter, fail-closed** — no UI ⇒ hard block, no prompt |

---

## Decision log

### Why secure-by-default with a single `--yolo` escape hatch

- Per-layer toggles drift. Users disable Layer 1 to fix one thing and forget
  Layer 2 was disabled too. One global switch is auditable.
- The visible warning banner on `--yolo` is non-negotiable: the user must
  always know when they're outside the sandbox.

**Alternative considered:** per-tool `--allow-X` flags (Claude Code style).
Rejected for now — too much surface area for a single-user developer tool.
Revisit if/when corp use cases need granularity.

### Why we don't deny `/tmp` reads

This was our initial instinct (other apps drop tokens, sockets, caches in
`/tmp` — pi could exfiltrate or fingerprint them). We reversed it after
checking what Claude Code and opencode actually do.

**Why neither denies `/tmp` reads:**

- Real per-user secrets on macOS live in `$TMPDIR` = `/var/folders/.../T/`,
  which already has 0700 perms enforced by the OS — pi can't reach other
  users' temp data without an explicit sandbox allow.
- `/tmp` itself is dominated by world-readable scaffolding: brew install
  scripts, Docker socket detection, IDE language-server caches, asdf shims,
  pip wheel caches. Denying reads breaks all of them.
- The remaining attack — another local process dropping a secret in
  world-readable `/tmp` — is a bug in *that* process, not something pi's
  sandbox should paper over.

**Cost we accept:** if a misbehaving local app does drop a secret in
`/tmp`, a prompt-injected pi could read it. Mitigation: don't run
secret-handling apps that misbehave; macOS `$TMPDIR` is the right place for
secrets and we don't allow reads there from outside the user's own
processes anyway.

### Why writes go to a dedicated `/private/tmp/pi-<uid>/`, not all of `/tmp`

- Prevents pi from planting files other tools subsequently ingest
  (cross-app supply-chain).
- Prevents `/tmp/foo` symlink/race attacks: pi can only write into a
  directory whose name only it knows.
- UID suffix makes the dir per-user on shared hosts.
- Setting `TMPDIR` to that dir means `mktemp(1)`, npm, pip, python all use
  it transparently — most tools work without changes.

**Cost:** any tool that hardcodes `/tmp/somefile` (ignoring `$TMPDIR`)
breaks. We surface a friendly error message pointing at `$TMPDIR` so the
model can correct itself instead of looping.

### Why `~/.pi-tmp` as a secondary fallback

`/private/tmp/...` clears on macOS reboot, which is fine for scratch but
occasionally annoying when iterating. `~/.pi-tmp/` survives reboots and is
discoverable (in the user's home), and it's writable by pi by design.
Cost: persistent files mean pi-generated junk accumulates. The user
manages this directory manually.

### Why `~/.pi/agent/**` instead of `~/.pi/**` in `denyWrite`

Found while writing the plan: the broad glob `~/.pi/**` accidentally
blocks `~/.pi/playground/`, which is the default working directory. Every
write — including legit edits to the user's project — fails with
"Operation not permitted". Scope the deny to only the directories that
*shouldn't* change at runtime: `~/.pi/agent/**` (extensions, skills) and
`~/.pi/config.json`. Sessions, logs, and the playground stay writable.

### Why we drop self-update inside pi (Option B)

Allowing `npm update -g` from inside the sandbox requires opening
`~/.npm`, `/opt/homebrew/lib/node_modules`, and `/opt/homebrew/bin`. That
gives any prompt-injected session the ability to overwrite pi itself with
arbitrary code — a privilege escalation path. Updating from a plain
terminal keeps the sandbox tight and the update path auditable.

### Why we keep MCP out of scope for now

MCP servers run as separate subprocesses with their own permissions and
network access; gating them needs either a per-server allowlist or a
proxy. Either is a meaningful design effort that deserves its own pass.
Until then, treat MCP servers as you would any other dev dependency:
review before installing, prefer official ones.

### Why path canonicalization walks up

The natural Layer 2 implementation is `realpathSync(absolutePath)`. That
fails the moment we evaluate a write target that doesn't exist yet, or a
symlink whose target is missing or unreadable. The naive fallback (try
realpath, on failure return the unresolved path) is exactly the bug that
lets `cwd/symlink-to-secret/foo` slip past denyRead when `foo` doesn't
exist.

Fix: walk up the path, attempting `realpathSync` on each ancestor in
turn. The first one that succeeds gives us the resolved prefix; we
re-join the trailing components. This catches symlink escape regardless
of whether the leaf or any intermediate exists, with no extra syscalls
on the happy path (the leaf is usually present).

Alternative considered: `lstat`-walk every component manually,
`readlink` each symlink. Equivalent result but ~5× more syscalls and
more code to get right (loops, absolute vs relative symlink targets).
The walk-up approach delegates that work to the OS resolver.

### Why subagent network is opt-in, not default-deny

The original plan said "subagents fail-closed; non-research subagents
have no network". After implementing Layer 2 we softened this to a
policy knob (`policy.subagent.network` = `"allow"` | `"deny"` |
`"research-only"`) defaulting to `"allow"`. Two reasons:

1. **`ctx.hasUI === false` doesn't only mean subagent.** It also covers
   `pi -p "..."` from a script, JSON mode, RPC mode without a TTY — all
   legitimate uses where a user expects network access.
2. **pi exposes no agent-name on `ctx`.** Without that, the
   research-allowlist check has to rely on a transcript heuristic
   (does the recent session text mention `librarian` / `scout`?). It's
   best-effort; making it the default would block too much.

Projects that genuinely run untrusted subagents add
`{ "subagent": { "network": "deny" } }` to their `.pi/sandbox.json`. When
pi adds first-class agent identity to `ctx`, we'll switch the default to
`"research-only"`.

### Why subagents are fail-closed by default (filesystem only)

Filesystem deny rules apply unchanged in every context, including
subagents and non-interactive runs. There's no UI to confirm and no
reason a code-modifying subagent should ever read `~/.ssh` or write
outside its worktree. Network is treated separately because the
headless detector (`ctx.hasUI === false`) catches both subagents and
legitimate scripted runs — see ["Why subagent network is opt-in"](#why-subagent-network-is-opt-in-not-default-deny)
above for the network-specific reasoning.

### Why a per-session confirm gates Chrome DevTools

`chrome_devtools_navigate_page` + `chrome_devtools_evaluate_script` are
effectively "arbitrary code execution in the user's logged-in browser",
which is broader than anything `bash` can do (think: read your authed
GitHub session, your bank, your email). One confirm per session is a
reasonable middle ground — the alternative (confirming every navigate)
would be unbearable. Read-only operations (`take_snapshot`, `screenshot`,
`list_pages`, console/network reads) stay open since they don't change
state.

### Why three-state ask-tier replaces "retry once unsandboxed"

The original plan ("if a sandboxed bash command fails with the
signature error, prompt to retry once unsandboxed") shipped briefly
as an idea but was superseded in 2026-04-27 by a richer ask-tier UX
that applies to **both Layer 1 and Layer 2**. The shipped design and
implementation live in [`PLAN-ask-tier-ux.md`](./PLAN-ask-tier-ux.md),
[`flow.md` § "Ask-tier prompt path"](./flow.md#ask-tier-prompt-path),
and [`implementation.md` § "Ask-tier UX"](./implementation.md#ask-tier-ux-shipped).

Why we changed direction:

1. **"Retry unsandboxed" only addressed Layer 1.** Layer 2 (the
   in-process `read`/`write`/`edit` gate) was the *more* common source
   of false positives — the v2 carve-outs for prompts, skills, etc.
   only paper over that, they don't solve it.
2. **"Retry once" gives the model a one-shot, no memory.** The same
   block recurs on the next call. Either we ask every time (annoying)
   or we widen the global policy (silently broadens the security
   posture). Neither is great.
3. **"Retry unsandboxed" is binary.** The shipped tier model lets us
   *grant a narrow always-permission scoped to the cwd* without
   nuking the whole sandbox for that command.

What we kept from the original idea:

- The sandbox should be **fast and quiet on the happy path** — still
  true. `default-allow` paths never see a prompt.
- The sandbox should be **informative on the unhappy path** — the
  prompt now *is* the informative path; the EPERM hint still prints
  for out-of-UI runs.
- **No global persistence from a prompt.** Project-local only. Global
  edits still require `apply-sandbox-patches*.sh`.

### Why an absolute-deny tier requires typing "i understand"

The "always" affordance is convenient, but for paths like
`~/.ssh/id_*` or `*.pem` we want a higher-friction gate even when
it's a single-shot allow. A `select`-style three-button prompt is too
easy to fat-finger; an `input`-style prompt that requires typing
`i understand` exactly:

- forces the user to read the message,
- prevents the model itself from synthesizing a valid response (it
  can't take the user's keystrokes), and
- refuses the `always` option entirely — SSH keys never get a
  permanent project-local override.

We intentionally hardcoded the patterns (`~/.ssh`, `~/.gnupg`,
`~/.aws`, `*.pem`, `*.key`) rather than making them configurable: a
user-controlled "absolute-deny list" defeats the purpose, since the
first thing prompt-injected models would try is to talk the user into
lowering the bar.

### Why ask-tier writes to `<cwd>/.pi/sandbox.json` under an additive `overrides` section

Both `sandbox/index.ts` (Layer 1) and `security-guard.ts` (Layer 2)
do a *shallow spread* merge of `~/.pi/agent/extensions/sandbox.json`
and `<cwd>/.pi/sandbox.json` for the `filesystem` and `network`
blocks. That means a project-local file with
`{ filesystem: { allowWrite: [...] } }` **replaces the global
allowWrite array entirely**. If we appended to it from the prompt,
we'd silently drop every global allowWrite entry the user expected
to inherit.

Fix: the prompt writes into a separate `overrides` block that *both
layers know to merge additively* on top of the flattened policy.
This is intentionally a separate shape from the existing schema:

- it makes "prompt-derived permission" easy to spot in a code review
  of `<cwd>/.pi/sandbox.json`,
- it lets us mark prompt-derived entries with metadata in v2 (timestamp,
  user that confirmed, expiry) without breaking the existing config
  shape,
- and it keeps the original config syntax untouched, so anything
  written by hand still works.

### Why the Layer 1 prompt fires *after* the bash tool result resolves

Layer 1 can't intercept before `sandbox-exec` returns EPERM — by the
time we know the command was blocked, the bash child process has
already finished. We have two choices for when to prompt:

1. **Before resolving the tool result** — hold the model's tool reply
   while we ask the user, then either re-run the command silently or
   resolve with success/failure based on the user's choice.
2. **After resolving** — send the EPERM hint back to the model, then
   ask the user. The user's choice affects only future calls.

We chose (2) because:

- Re-running side-effecting commands (`make install`, `git push`)
  silently is hostile. The model needs to make the retry call itself.
- The model gets the EPERM context and can decide to retry, abandon,
  or do something else. The user's `always` answer reshapes the
  sandbox for that decision.
- Layer 2 gets behaviour (1) instead, because the in-process gate runs
  *before* the side effect — there's nothing to roll back.

### Why Layer 1 supports `always` but not `yes-this-once`

For Layer 2 the three-state prompt is `yes / no / always`, where `yes`
allows the current call without persisting. Layer 1 only offers
`always / no`:

- The blocked bash call has already returned EPERM by the time we
  prompt. We can't "allow this once" — the side effect didn't happen.
- We could re-run the command, but a) we don't have its argv handy in
  a clean form, and b) re-running things like `pip install` or any
  command with `>` redirection mid-pipeline is unsafe.
- The model's natural retry (after seeing the EPERM and the user's
  notification) covers the same ground.

---

## Risks we're knowingly accepting

- **`sandbox-exec` is deprecated by Apple** but still functional and is the
  same tool Claude Code uses in production. If Apple removes it, the whole
  ecosystem is affected; we'll migrate together.
- **`$TMPDIR` honoring is not universal.** Some legacy tools hardcode
  `/tmp`. We surface a clear error rather than silently allow `/tmp`.
- **Raw-IP egress bypasses the domain allowlist.** `sandbox-runtime`
  matches network rules by hostname; a `curl http://1.1.1.1` or
  `nc 8.8.8.8 53` reaches its destination because no DNS lookup happens.
  An attacker who knows the IP of a target service (or one of the
  allowlisted hosts behind a CDN) can reach it. v1 mitigation: rely on
  the model not knowing useful IPs by heart; v2: add an explicit
  `deniedDomains: ["*"]` fallback when `allowedDomains` is set, or wrap
  bash with a network namespace that forces DNS-based filtering.
- **`fetch_content` redirects.** The Layer 2 guard sees only the input URL.
  A 302 to `evil.example.com` would still load. v1 documents this; v2
  could resolve redirects before fetching.
- **In-process tools currently bypass everything.** ~~Until Layer 2
  ships~~ Layer 2 has shipped (and now has an ask-tier prompt path).
  This row is preserved historically; today the gap is `bash cat
  ~/.config/<sensitive>` (Scenario A in `flow.md`), not in-process
  tools.

## Things we explicitly chose NOT to do

- **Per-command interactive prompts (Claude Code style).** The shipped
  three-state ask-tier (yes / no / always-for-this-cwd) is the closest
  we got to per-command prompts — but only on actual blocks, never on
  routine calls. The principle stands: prompt only on rare events,
  never train users to click yes reflexively.
- **Per-tool granularity ("always allow `gh` but ask for `kubectl`").**
  The tier model is the abstraction — paths and URLs, not commands.
  Adding a per-tool axis would multiply the policy surface for
  marginal gain.
- **Network proxy / MITM-style network policy.** Higher fidelity than
  domain allowlist (could enforce per-URL rules), but invasive and brittle.
  Domain allowlist is the right power/effort tradeoff for v1.
- **Containerization (Docker / Lima).** Real isolation but kills
  performance and developer ergonomics. Out of scope for an inner-loop
  coding tool.
- **Audit log as a security boundary.** The audit log was added in the
  ask-tier UX (so we can see what's been allowed), but it's an
  investigative aid, not evidence — a determined model in YOLO mode
  could truncate it. We didn't promote it to a security control.
- **Audit log expiry / rotation.** Tail-and-forget JSONL is fine at the
  rate we generate it. Add log rotation if it becomes a problem.
- **Expiring "always" entries.** Project-local `overrides` persist
  forever in v1. Auditable via `/security`; revisit if it becomes a
  source of footguns.
