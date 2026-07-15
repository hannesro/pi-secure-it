# PLAN: Ask-tier UX for sandbox & security-guard blocks

> **Status (2026-04-27): SHIPPED for Layers 1 & 2.** Only tests (Step 8)
> remain open. See
> [`CHANGES-ask-tier-ux.md`](./CHANGES-ask-tier-ux.md) for what landed,
> [`flow.md` § "Ask-tier prompt path"](./flow.md#ask-tier-prompt-path),
> [`implementation.md` § "Ask-tier UX"](./implementation.md#ask-tier-ux-shipped),
> and [`tradeoffs.md` § "Three-state ask-tier vs retry-once"](./tradeoffs.md#why-three-state-ask-tier-replaces-retry-once-unsandboxed)
> for the why. This file is preserved as the design record.

## Goal

When a tool call is blocked by Layer 1 (sandbox) or Layer 2
(security-guard), prompt the user to decide what to do — instead of
returning a hard error and forcing the model to give up or work around
it. Match the UX pattern of Claude Code / opencode where appropriate.

## Problem statement

Today, blocks return a hard `{ ok: false, reason: "..." }` to the model.
This works but has three failure modes:

1. **Legitimate work gets blocked.** Agent wants to edit
   `~/.pi/agent/prompts/frontend_review.md`. Layer 2 says no. User has
   to leave pi, run an external script, restart. Friction.
2. **Model improvises around the block.** Sees "denyWrite matched", tries
   `bash` instead of `edit`, finds a workaround, no human in the loop.
   Defeats the security model silently.
3. **One-off needs require nuking everything.** Need to read one file in
   `~/.config`? Today's only escape is `--yolo`, which disables ALL
   four layers for the whole session. Way too coarse.

## Design principles

- **Ask only when there's a UI.** `ctx.hasUI === false` (scripted
  `pi -p` runs, subagents, CI) → no prompt, hard block as today.
- **Default = deny.** Prompt timeout, "n", Esc, Ctrl-C → block.
- **Three-state answer.** Not just yes/no:
  - `yes` — allow this one call, no policy change
  - `no` — block (default)
  - `always` — persist as project-local policy in `<cwd>/.pi/sandbox.json`
- **Never persist globally from a prompt.** "always" writes
  `<cwd>/.pi/sandbox.json` only. Editing `~/.pi/agent/extensions/sandbox.json`
  still requires a deliberate external action (apply-sandbox-patches.sh
  pattern).
- **Include the reason in the prompt.** User must see *why* it's blocked
  to make a judgment call.
- **Show the path/URL/command verbatim.** No truncation of the thing
  being decided about.
- **Audit every "yes"/"always".** Append to `~/.pi/agent/audit.log` so
  there's a paper trail.

## Scope: which blocks get a prompt?

| Block source | Prompt? | Rationale |
|---|---|---|
| Layer 1 bash filesystem | ✅ yes | Common, expected (tool config dirs) |
| Layer 1 bash network | ✅ yes | Common (new package registry, CDN) |
| Layer 2 `denyRead` | ⚠️ careful | These are *intentional* hard denies (`~/.ssh`). Prompt with extra warning. |
| Layer 2 `modelDenyRead` | ✅ yes | These are "default deny but user override OK" tier |
| Layer 2 `denyWrite` | ✅ yes | Same |
| Layer 2 URL allowlist | ✅ yes | Common (new docs site, allowlisted-by-domain) |
| Layer 3 subagent network | ❌ no | No UI by definition |

Tiers (from strictest to most permissive):

```
absolute-deny   →  no prompt ever (e.g. ~/.ssh/id_rsa even with prompt
                   shows giant red warning and requires typing "yes")
default-deny    →  normal three-state prompt
default-allow   →  no block, no prompt (today's allowed paths)
```

Question for design review: should `denyRead` for `~/.ssh` be in the
absolute-deny tier? Probably yes — if model wants to read SSH keys,
that's almost always exfiltration. Make it possible but unergonomic.

## UX

### Inline prompt format

```
┌─ Sandbox / security-guard prompt ───────────────────────────────────┐
│ Layer 2 (security-guard) wants to BLOCK this:                       │
│                                                                     │
│   Tool:   edit                                                      │
│   Path:   /Users/hhr1fe/.pi/agent/prompts/frontend_review.md        │
│   Reason: denyWrite matched "~/.pi/agent/extensions/**"             │
│                                                                     │
│ Allow?                                                              │
│   [y] yes, this once                                                │
│   [n] no (default, Esc/Ctrl-C)                                      │
│   [a] always for this cwd → writes ./pi/sandbox.json                │
│                                                                     │
│ Choice [y/N/a]: _                                                   │
└─────────────────────────────────────────────────────────────────────┘
```

For ABSOLUTE-DENY tier (e.g. `~/.ssh/id_rsa`):

```
┌─ ⚠️  HIGH-RISK BLOCK ───────────────────────────────────────────────┐
│ Layer 2 wants to BLOCK this — this is a sensitive credential file.  │
│                                                                     │
│   Tool:   read                                                      │
│   Path:   /Users/hhr1fe/.ssh/id_rsa                                 │
│   Reason: denyRead matched "~/.ssh"                                 │
│                                                                     │
│ Reading SSH private keys is almost always exfiltration. To allow:   │
│                                                                     │
│ Type "i understand" to allow this once: _                           │
└─────────────────────────────────────────────────────────────────────┘
```

### Auto-discard cases (no prompt)

- `ctx.hasUI === false` → block, return reason
- Inside a parallel/async subagent run → block, return reason
- Inside automated test mode (`PI_TEST=1` env) → block, return reason

## Implementation sketch

### Where it lives

- **Layer 2 prompts**: in `~/.pi/agent/extensions/security-guard.ts`, in
  the `tool_call` hook before returning `{ block: true }`.
- **Layer 1 prompts**: in `~/.pi/agent/extensions/sandbox/index.ts`,
  after sandbox-exec exits nonzero AND `outputTail` matches the
  sandbox-block regex.

### The pi UI primitive needed

Question: does `ctx` expose a way to prompt the user? Need to check pi
extension docs. Options:

1. **`ctx.prompt(opts)`** — if pi has this, just use it.
2. **Custom slash command** — print a marker, wait for user to type
   `/sandbox-allow <id>` or `/sandbox-deny <id>`. Awkward.
3. **stdin read with timeout** — bypasses pi's UI, brittle in TUI mode.
4. **Tool result that includes a "needs-confirmation" payload** — pi
   renders a confirm prompt natively. Cleanest if supported.

→ **Action item**: read `/opt/homebrew/lib/node_modules/@mariozechner/pi-coding-agent/docs/extensions.md` and `tui.md` to see what's exposed on `ctx`.

### Persistence shape (project-local override)

`<cwd>/.pi/sandbox.json` overrides global `~/.pi/agent/extensions/sandbox.json`
by **adding** to allow lists and **removing** from deny lists for the
current cwd only:

```json
{
  "filesystem": {
    "allowWrite": ["~/.pi/agent/prompts/**"],
    "modelDenyReadOverride": ["~/.config/gh/hosts.yml"]
  },
  "network": {
    "allowedDomains": ["docs.example.com"]
  }
}
```

Question: do we have policy merging today? Check what
`SandboxManager.initialize` does with project-local config. If not, add
it.

### Audit log

```jsonl
{"ts":"2026-04-27T14:50:00Z","layer":2,"tool":"edit","path":"~/.pi/agent/prompts/frontend_review.md","decision":"yes","cwd":"/Users/hhr1fe/.pi/playground"}
{"ts":"2026-04-27T14:51:23Z","layer":2,"tool":"edit","path":"~/.pi/agent/prompts/x.md","decision":"always","cwd":"/Users/hhr1fe/.pi/playground","persisted_to":"/Users/hhr1fe/.pi/playground/.pi/sandbox.json"}
{"ts":"2026-04-27T14:52:01Z","layer":1,"tool":"bash","command":"gh pr view 99","decision":"no"}
```

Location: `~/.pi/agent/audit.log` (write-only append from extensions).
Add to `denyWrite` itself (extensions/** carve-out covers it) so the
model can't tamper. Actually it's *under* `~/.pi/agent/` not under
`extensions/` — need to ensure the v2 carve-out doesn't accidentally
allow agent to write here. Add `~/.pi/agent/audit.log` explicitly to
`denyWrite`.

## Threat model considerations

### "Prompt fatigue → always-yes"
If users get prompted constantly they'll start hitting "always" without
reading. Mitigation: tune the default policy so the prompt is *rare*.
The whole point of v2 patch (allowing tool config dirs, prompts/, skills/)
is to keep prompts to genuinely sensitive cases.

Target: < 1 prompt per typical 30-minute session.

### "Model crafts a misleading prompt context"
The block-reason text is generated by the security-guard, not the
model. But the *path* shown is what the model passed in. A model could
craft `read("./innocent.txt\n... [actually let me read your SSH key]")`
to confuse the prompt UI. Mitigation: render path in a quoted/escaped
box, never interpret newlines or terminal escapes.

### "User hits 'always' for cwd, forgets, later runs untrusted prompt"
Project-local `.pi/sandbox.json` persists. New session in same cwd
inherits the looser policy. Mitigation: `/security` command lists
project overrides prominently. Possibly: expire project-local entries
after N days unless re-confirmed. Defer.

### "Subagent gets prompted, parent doesn't see"
Subagents have no UI → never prompted → hard block. Good.

### "Prompt during a streaming tool result"
What if the model is in the middle of a multi-step plan? Prompt
interrupts. UX-wise: pause the stream, prompt, resume. pi's TUI should
already handle this if `ctx.prompt` is the right primitive.

## Effort & sequencing

| Step | Status |
|---|---|
| 1. Read pi extensions docs to find prompt primitive | ✅ done — `ctx.ui.select/confirm/input` with `{timeout}` |
| 2. Decide tier model (absolute-deny vs default-deny) | ✅ done — three tiers shipped |
| 3. Implement Layer 2 prompt path in security-guard.ts | ✅ done — `askOrBlock` wraps every block site |
| 4. Implement project-local policy merging | ✅ done — additive `overrides` section |
| 5. Implement Layer 1 prompt path in sandbox/index.ts | ✅ done — post-EPERM prompt + live `SandboxManager.reset()/initialize()` |
| 6. Audit log writing | ✅ done — JSONL at `~/.pi/agent/audit.log`, both layers |
| 7. Update `/security` to show project overrides + recent audit | ✅ done — `/security` and `/sandbox` reflect overrides |
| 8. Tests: prompt path with mocked ctx, persistence shape, tier escalation | ❌ **not done** — next session |
| 9. Update docs (flow.md, implementation.md, tradeoffs.md) | ✅ done (this update) |

## Open questions

1. ~~Does `ctx.prompt` exist in pi?~~ **Resolved**: `ctx.ui.select(title, options, {timeout})`, `ctx.ui.confirm(title, msg, {timeout})`, `ctx.ui.input(title, placeholder, {timeout})`. `ctx.hasUI` is `false` in `-p`/JSON/subagent transports → no prompts there. Timeout returns `undefined`/`false` (= default deny). All in extensions.md §"Custom UI" / §"ctx.hasUI".
2. ~~Does pi merge project-local + global config?~~ **Resolved**: yes for the bash sandbox extension (`sandbox/index.ts` does `deepMerge(deepMerge(DEFAULT, global), project)` from `~/.pi/agent/extensions/sandbox.json` + `<cwd>/.pi/sandbox.json`). Layer 2 (security-guard.ts) does its own *shallow* spread merge of the same files, which **replaces arrays wholesale** — so persisting an "always" decision by appending to `denyRead` in project-local would replace the global list entirely. Use a dedicated additive `overrides` section instead (see Implementation sketch).
3. Should "always" entries in project-local config expire? (Defer)
4. Should there be a global "always" tier, or is project-local the ceiling? **Decision**: project-local only. Global edits still require `apply-sandbox-patches*.sh` (deliberate external action).
5. Does absolute-deny need its own config knob? **Decision**: hardcoded for v1. Patterns: `~/.ssh`, `~/.gnupg`, `~/.aws`, `*.pem`, `*.key`. Bypass requires typing `i understand` exactly.
6. How do we surface in TUI that a project-local override is active? Status line marker? (Defer)

## Out of scope (for this iteration)

- Layer 4 (Chrome DevTools confirm) — separate plan
- "Paranoid mode" pre-scanning bash for credential reads — separate plan
- Outbound content inspection / DLP — fundamentally out of scope
- Per-tool granular prompts (e.g. "always allow `gh` but ask for `kubectl`") — too complex for v1; tier model is the abstraction
