# Pi Security — Implementation Reference

Concrete file paths, configs, and code patches that realize the plan in
[`../../SECURITY_PLAN.md`](../../SECURITY_PLAN.md). Read alongside
[`tradeoffs.md`](./tradeoffs.md) for the *why*.

Last updated: 2026-04-27

---

## Files involved

| Path | Purpose |
|---|---|
| `~/.pi/agent/extensions/sandbox.json` | Global policy (network + FS) |
| `<project>/.pi/sandbox.json` | Per-project overrides (merged on top); also written by ask-tier prompts under an additive `overrides` section |
| `~/.pi/agent/extensions/sandbox/index.ts` | The bash-wrapping extension (Layer 1) + Layer 1 ask-tier prompt |
| `~/.pi/agent/extensions/sandbox/package.json` | Pulls `@anthropic-ai/sandbox-runtime` |
| `~/.pi/config.json` | Auto-loads the extension on every `pi` launch |
| `~/.pi/agent/extensions/security-guard.ts` | Layer 2 — in-process tool gate + Layer 2 ask-tier prompt |
| `~/.pi/agent/audit.log` | Append-only JSONL audit log of every ask-tier decision (mode 600) |
| `~/.pi/playground/scripts/apply-ask-tier.sh` | Idempotent installer for the staged ask-tier patches |

---

## Layer 1 — bash sandbox (current)

### What it covers

Every invocation of pi's `bash` tool is wrapped by `SandboxManager`. This
includes:

- Model-issued bash tool calls (the normal path).
- The **`!` shell escape** at the pi prompt (e.g. `!ls`, `!bash run-tests.sh`).
  `!` skips model approval but still goes through the wrapped bash tool, so
  the sandbox applies. You can rely on this when running diagnostics during
  a sensitive session.

It does **not** cover the in-process tools (`read`, `write`, `edit`,
`fetch_content`, `web_search`) — those are Layer 2's job.

### Active config (`~/.pi/agent/extensions/sandbox.json`)

```json
{
  "enabled": true,
  "network": {
    "allowedDomains": [
      "registry.npmjs.org", "registry.yarnpkg.com",
      "npmjs.org", "*.npmjs.org",
      "pypi.org", "*.pypi.org", "files.pythonhosted.org",
      "github.com", "*.github.com",
      "api.github.com",
      "raw.githubusercontent.com",
      "objects.githubusercontent.com",
      "codeload.github.com",
      "crates.io", "static.crates.io",
      "proxy.golang.org", "sum.golang.org"
    ],
    "deniedDomains": []
  },
  "filesystem": {
    "denyRead": [
      "~/.ssh", "~/.aws", "~/.gnupg",
      "~/.config/gh", "~/.netrc",
      "~/.kube", "~/.docker/config.json"
    ],
    "allowWrite": [
      ".",
      "/private/tmp/pi-501",
      "~/.pi-tmp"
    ],
    "denyWrite": [
      ".env", ".env.*",
      "*.pem", "*.key", "*.p12", "*.pfx",
      "~/.pi/agent/**",
      "~/.pi/config.json",
      "~/.bashrc", "~/.zshrc", "~/.profile"
    ]
  }
}
```

### Why these specific paths

- **`/private/tmp/pi-$UID`** — dedicated scratch dir, mirrors Claude Code's
  `tmp/claude-<uid>` pattern. UID suffix prevents collisions on shared hosts.
  Note we use `/private/tmp/...` (the real path) because `/tmp` is a symlink
  on macOS and `sandbox-exec` resolves real paths.
- **`~/.pi-tmp`** — a stable, user-known fallback in case a tool ignores
  `$TMPDIR`. Pre-create with `mkdir -p ~/.pi-tmp && chmod 700 ~/.pi-tmp`.
- **`/tmp` is intentionally NOT in `denyRead`** — see
  [tradeoffs.md § "Why we don't deny /tmp reads"](./tradeoffs.md#why-we-dont-deny-tmp-reads).
- **`~/.pi/agent/**` instead of `~/.pi/**`** — the broader glob accidentally
  blocks `~/.pi/playground/` (the default working directory), preventing all
  writes inside cwd. Scope the deny only to the agent/config files we
  actually want to protect.

### One-time setup commands

Must run **outside pi** (or with `pi --yolo`), since the sandbox blocks
writes to these paths by design:

```bash
# Dedicated tmp dir (run once)
UID_NUM=$(id -u)
mkdir -p "/private/tmp/pi-$UID_NUM" && chmod 700 "/private/tmp/pi-$UID_NUM"
mkdir -p ~/.pi-tmp && chmod 700 ~/.pi-tmp
```

If you forget, the first sandboxed bash call will fail with the friendly
hint pointing at the missing `$TMPDIR`.

### Required code patch — inject `TMPDIR` and surface helpful errors

File: `~/.pi/agent/extensions/sandbox/index.ts`. Inside `createSandboxedBashOps()`:

```ts
async exec(command, cwd, { onData, signal, timeout }) {
  if (!existsSync(cwd)) {
    throw new Error(`Working directory does not exist: ${cwd}`);
  }
  const wrappedCommand = await SandboxManager.wrapWithSandbox(command);

  const uid = process.getuid?.() ?? 0;
  const piTmp = `/private/tmp/pi-${uid}`;

  return new Promise((resolve, reject) => {
    const child = spawn("bash", ["-c", wrappedCommand], {
      cwd,
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, TMPDIR: `${piTmp}/` },   // ← new
    });

    let stderrTail = "";
    const captureStderr = (chunk: Buffer) => {
      stderrTail = (stderrTail + chunk.toString()).slice(-2048);
      onData(chunk);
    };
    child.stdout?.on("data", onData);
    child.stderr?.on("data", captureStderr);

    // ... existing timeout / abort handling unchanged ...

    child.on("close", (code) => {
      // ... existing cleanup ...
      // Friendly hint when the sandbox bites
      if (/operation not permitted/i.test(stderrTail)) {
        const hint =
          `\n💡 pi-sandbox: write blocked outside allowed paths.\n` +
          `   Use $TMPDIR (= ${piTmp}/) for scratch files,\n` +
          `   or write inside the project directory (${cwd}).\n` +
          `   See ~/.pi/agent/extensions/sandbox.json for the full policy.\n`;
        onData(Buffer.from(hint));
      }
      // ... existing resolve/reject ...
    });
  });
},
```

> Restart pi after editing `index.ts`. The extension is loaded once at
> session start.

---

## Layer 2 — In-process guard (shipped)

**File:** `~/.pi/agent/extensions/security-guard.ts` (auto-discovered).
**No `package.json` needed** — zero deps beyond `@mariozechner/pi-coding-agent`,
which pi already provides at runtime. Drop the file in and `/reload`
(or restart pi) picks it up.

### What it gates

| Tool | Gate |
|---|---|
| `read` | path checked against `denyRead` |
| `write` | path checked against `denyWrite` AND must be inside an `allowWrite` root |
| `edit` | same as `write` |
| `fetch_content` | every entry of `url` + `urls[]` checked against domain allow/deny lists |
| `web_search` | passes through (search provider is out of scope for v1); follow-on `fetch_content` is the catchable surface |
| `get_search_content` | URL checked when present |

Layer 3 (subagent posture) is folded in: when `ctx.hasUI === false`,
`policy.subagent.network` decides whether network-bound tools are allowed.
Default `"allow"` keeps existing behavior; opt into `"deny"` or
`"research-only"` per project.

### Path-resolution design

```ts
function canonicalize(p: string, cwd: string): string {
  const abs = isAbsolute(p) ? p : resolve(cwd, p);
  const trail: string[] = [];
  let cur = abs;
  while (true) {
    try {
      const real = realpathSync(cur);
      return trail.length ? `${real}/${trail.slice().reverse().join("/")}` : real;
    } catch {
      const parent = dirname(cur);
      if (parent === cur) return abs; // reached root; give up
      trail.push(basename(cur));
      cur = parent;
    }
  }
}
```

Why walk up: `realpathSync` requires the *whole path* to exist, so a naive
`realpathSync(abs)` fails when the target is a file we're about to create
or a symlink whose final-leaf doesn't exist yet. Walking up to the
deepest existing ancestor and re-joining the trailing components defeats
`cwd/symlink-to-secret/anything` regardless of whether `anything` exists.
See [tradeoffs.md § "Why path canonicalization walks up"](./tradeoffs.md#why-path-canonicalization-walks-up).

### Glob rules

The matcher supports `*` (single segment), `**` (any depth), and `?`
(single char), case-insensitive on macOS. Patterns are interpreted as:

- Starts with `/` or `~/` → **absolute** path or glob match.
- Equals `.` → matches anything inside `cwd` (after canonicalization).
- Otherwise → **basename** match (e.g. `*.pem`, `.env.*`).

### Subagent (Layer 3) policy knob

Add to `~/.pi/agent/extensions/sandbox.json` to opt in:

```json
{
  "subagent": { "network": "deny" }
  // or "research-only" — allows network only when a known
  // research-agent marker (`librarian`, `scout`, `researcher`) is in the
  // recent session transcript. Best-effort heuristic; v2 should plumb
  // agent identity through `ctx`.
}
```

### Slash command

`/security` prints active Layer 2 status, the cwd, the merged FS and
network policy, the current subagent.network mode, **the project-local
`overrides` section if any, and the last 10 audit-log entries**.

---

## Ask-tier UX (shipped)

Design: see [`PLAN-ask-tier-ux.md`](./PLAN-ask-tier-ux.md).
Flow / sequence diagrams: see [`flow.md` § "Ask-tier prompt path"](./flow.md#ask-tier-prompt-path).
Apply / rollback: `~/.pi/playground/scripts/apply-ask-tier.sh`.

### Tier model (both layers)

```ts
// security-guard.ts
const ABSOLUTE_DENY_PATTERNS = [
  "~/.ssh", "~/.gnupg", "~/.aws", "*.pem", "*.key",
];
```

- **absolute-deny** — `ctx.ui.input("Type 'i understand' to allow this once")`. Refuses `always`. Audits the typed answer and the decision.
- **default-deny** — `ctx.ui.select(reason, ["yes", "no (default)", "always for this cwd"], { timeout: 60_000 })`.
- **default-allow** — never reaches the gate.

### `ctx.hasUI === false` ⇒ hard block

No prompt in `pi -p`, JSON mode, RPC mode, or any subagent. The audit
line is still written with `decision: "no"` and a `no_ui: true` field.

### Persistence: project-local `overrides` section

Why a dedicated section: both layers' existing config merge is a *shallow
spread* of `filesystem` / `network` keys, which would replace the
global arrays wholesale if we appended to them in the project-local
file. Instead, both layers read an additive `overrides` block and merge
it on top of the flattened policy.

```jsonc
// <cwd>/.pi/sandbox.json (written by either layer's prompt)
{
  "overrides": {
    "allowRead":    ["/abs/path/file"],   // Layer 2 only
    "allowWrite":   ["/abs/path/dir"],    // both layers
    "allowDomains": ["docs.example.com"]  // both layers
  }
}
```

`security-guard.ts` checks `overrides.{allowRead, allowWrite,
allowDomains}` *before* the deny patterns. `sandbox/index.ts` calls
`foldOverrides(config)` which appends `overrides.allowWrite` /
`overrides.allowDomains` into the flat arrays before passing the config
to `SandboxManager.initialize()`. `overrides.allowRead` is **not**
folded into Layer 1 (would require *removing* from `denyRead`, which
would let a Layer 2 model-tool "always" widen the OS sandbox).

### Layer 1 live reload

When the user picks `always` in Layer 1, the extension calls
`SandboxManager.reset()` then `SandboxManager.initialize(newConfig)`
so the *next* bash command picks up the override without a pi restart.
The failed bash call is **not** retried automatically — we don't have
the original argv at hand and re-running side-effecting commands is
hostile UX. The model retries naturally on its next turn.

### Audit log

`~/.pi/agent/audit.log` (mode 600, append-only JSONL). Schema:

```ts
interface AuditLine {
  ts: string;            // ISO 8601
  layer: 1 | 2;
  tool: "read" | "write" | "edit" | "fetch_content" | "get_search_content" | "bash";
  subject: string;       // canonicalised path or hostname
  reason?: string;       // "denyWrite" | "absolute-deny" | "url-not-allowed" | ...
  decision: "yes" | "no" | "always";
  cwd: string;
  persisted_to?: string; // <cwd>/.pi/sandbox.json (only on "always")
  override?: { kind: "allowRead" | "allowWrite" | "allowDomains"; value: string };
  no_ui?: true;          // hard-blocked because ctx.hasUI === false
  error?: string;        // persistence failed
}
```

The audit log is **not** itself a security boundary — it sits below
Layer 2's denyWrite (the v2 carve-out for `~/.pi/agent/**` covers it),
but Layer 1's bash sandbox would in principle let a determined model
truncate it. Treat as an investigative aid, not as evidence.

### Wiring summary

| Block site | Layer | Tier check | Prompt fn |
|---|---|---|---|
| `read` denyRead/modelDenyRead | 2 | `isAbsoluteDeny()` first | `askOrBlock(ctx, kind="read", absPath, reason)` |
| `write` / `edit` denyWrite or outside allowWrite | 2 | `isAbsoluteDeny()` first | `askOrBlock(ctx, kind="write", absPath, reason)` |
| `fetch_content` / `get_search_content` URL not allowed | 2 | none (no abs-deny tier for URLs) | `askOrBlock(ctx, kind="url", host, reason)` |
| Bash EPERM/EACCES on stderr | 1 | none (sandbox already returned) | post-resolve `ctx.ui.select` → `persistAndReload(absPath)` |

### Restart vs reload semantics

- **Layer 2 overrides** take effect *immediately* on the same process — `loadPolicy` runs per `tool_call`.
- **Layer 1 overrides** require `SandboxManager.reset()`/`initialize()`. The extension does this automatically when `always` is picked. A pi restart (or `/sandbox-reload` if added) is only needed if you hand-edit `<cwd>/.pi/sandbox.json`.

### Tests

- 13 path-matcher unit tests (prefix vs basename vs glob vs `~` expansion).
- 8 URL allowlist tests (`*.github.com`, false-prefix safety, denylist).
- 5 symlink-escape tests (leaf exists, leaf missing, deep nonexistent).
- All pass under Node 22+. Live end-to-end via the actual pi tools is
  manual today; see [`testing.md` § "Layer 2"](./testing.md#layer-2--in-process-tool-guard).
- **Ask-tier UX has no automated tests yet** — PLAN Step 8. Manual smoke
  test in [`CHANGES-ask-tier-ux.md`](./CHANGES-ask-tier-ux.md).


## Layer 4 — Browser gate (planned)

Per-session confirmation for `chrome_devtools_*` mutators:

```ts
const MUTATING = new Set([
  "chrome_devtools_navigate_page",
  "chrome_devtools_new_page",
  "chrome_devtools_evaluate_script",
  "chrome_devtools_click",
  "chrome_devtools_fill",
  "chrome_devtools_fill_form",
  "chrome_devtools_upload_file",
  "chrome_devtools_handle_dialog",
  "chrome_devtools_press_key",
  "chrome_devtools_drag",
]);

let browserApprovedThisSession = false;

pi.on("tool_call", async (event, ctx) => {
  if (!MUTATING.has(event.name)) return;
  if (browserApprovedThisSession) return;
  if (!ctx.hasUI) return { block: true, reason: "Browser tools disabled in subagents" };
  const ok = await ctx.ui.confirm(
    "Allow browser automation?",
    "This session will be able to navigate, click, type, and run JS in your browser.",
  );
  if (!ok) return { block: true, reason: "User declined browser access" };
  browserApprovedThisSession = true;
});
```

---

## Auto-loading on every `pi` launch

`~/.pi/config.json`:

```json
{
  "extensions": [
    "~/.pi/agent/extensions/sandbox",
    "~/.pi/agent/extensions/security-guard.ts"
  ]
}
```

---

## `--yolo` flag (single escape hatch)

Replace the per-extension `--no-sandbox` with one global flag, registered
once and read by every layer:

```ts
// in sandbox/index.ts and security-guard.ts
const yolo = pi.getFlag("yolo") as boolean;
if (yolo) {
  ctx.ui.notify(
    "⚠️  YOLO mode — all pi security layers disabled for this session.",
    "warning",
  );
  return; // skip sandbox init / tool gate
}
```

Keep `--no-sandbox` as a hidden alias for one release for muscle memory.

---

## Verification commands

```bash
# After editing index.ts, restart pi, then in a pi session:
/sandbox                                       # show active policy

# Smoke tests
echo "x" > /tmp/foo                            # blocked (use $TMPDIR)
echo "x" > "$TMPDIR/foo" && cat "$TMPDIR/foo"  # works (dedicated dir)
cat ~/.ssh/id_ed25519                          # blocked
curl -sS https://api.github.com | head         # works
curl -sS https://example.com | head            # blocked
```

A complete test suite (incl. symlink escape, network allowlist, error
hint surfacing) lives in [`testing.md`](./testing.md), with a runnable
`run-tests.sh` block.
