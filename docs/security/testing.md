# Pi Security — Test Matrix

Smoke and regression tests for the layers defined in
[`../../SECURITY_PLAN.md`](../../SECURITY_PLAN.md). Each test is a
copy-pasteable shell snippet with the expected pass condition. Run from
inside a `pi` session unless the test says otherwise.

Last updated: 2026-04-27

---

## How to run

Two ways:

1. **Manual** — paste the snippet into pi (as an instruction to the model
   like `run: <snippet>`) and check the result against the expected outcome.
2. **Scripted** — run [`run-tests.sh`](#full-script) below in a pi bash tool
   call. Each test prints `PASS` / `FAIL` with a one-line reason.

### `!` shell escape

Both model-issued tool calls and the **`!` shell escape** (e.g. typing
`!bash docs/security/run-tests.sh` at the pi prompt) go through the same
wrapped bash tool, so both are sandboxed identically. The only difference
is that `!` skips model approval — keystroke goes straight to the tool.

This means you can safely use `!` to drive the test suite during a
session; you're not bypassing the sandbox by doing so.

> **Restart pi** after editing `sandbox.json` or
> `~/.pi/agent/extensions/sandbox/index.ts`. Layer 1 config is loaded once
> at session start.

A test is **PASS** if its actual outcome matches the **Expected** column.
A "blocked" test passes when the command fails with the sandbox's
signature error (`Operation not permitted`, `403`, or the friendly hint).

---

## Layer 1 — bash sandbox

### Filesystem reads

| # | Command | Expected | Why |
|---|---|---|---|
| R1 | `cat ~/.ssh/id_ed25519` (or any file you have) | **blocked** | denyRead `~/.ssh` |
| R2 | `cat ~/.aws/credentials` (create dummy first if needed) | **blocked** | denyRead `~/.aws` |
| R3 | `cat ~/.gnupg/gpg.conf` | **blocked** | denyRead `~/.gnupg` |
| R4 | `cat ~/.netrc` | **blocked** | denyRead `~/.netrc` |
| R5 | `cat /tmp/some-file` (drop a dummy first via `--yolo`) | **allowed** | `/tmp` reads intentionally open ([why](./tradeoffs.md#why-we-dont-deny-tmp-reads)) |
| R6 | `cat ./SECURITY_PLAN.md` | **allowed** | cwd readable |
| R7 | `cat /etc/hosts` | **allowed** | system reads not denied |

### Filesystem writes

| # | Command | Expected | Why |
|---|---|---|---|
| W1 | `echo x > ~/.bashrc.test` | **blocked** | denyWrite `~/.bashrc*` |
| W2 | `echo x > ~/.zshrc.test` | **blocked** | denyWrite `~/.zshrc*` |
| W3 | `echo x > ./.env.test` | **blocked** | denyWrite `.env.*` |
| W4 | `echo x > ./test.pem` | **blocked** | denyWrite `*.pem` |
| W5 | `echo x > ~/.pi/agent/test.txt` | **blocked** | denyWrite `~/.pi/agent/**` |
| W6 | `echo x > ~/.pi/playground/foo.txt` | **allowed** | playground is the cwd, not denied |
| W7 | `echo x > /tmp/pi-test` | **blocked** | `/tmp` not in allowWrite |
| W8 | `echo x > "$TMPDIR/pi-test" && cat "$TMPDIR/pi-test"` | **allowed** | dedicated `/private/tmp/pi-<uid>/` |
| W9 | `echo x > ~/.pi-tmp/foo` | **allowed** | persistent fallback |
| W10 | `echo x > /etc/passwd.test` | **blocked** | system path not in allowWrite |
| W11 | `echo x > ../escape.txt` | **blocked** | escapes cwd |

### Friendly error hint (post-Layer-1-polish)

Must be tested **manually** with a single bash invocation — the hint is
emitted once when the wrapped bash tool exits, so a multi-command script
won't see it on individual inner commands.

| # | Command (run as a single pi bash call, e.g. `!echo x > /tmp/foo`) | Expected |
|---|---|---|
| H1 | `echo x > /tmp/foo` | **blocked** AND output contains `💡 pi-sandbox` and `$TMPDIR` |
| H2 | `echo x > /etc/foo` | **blocked** AND output contains the hint |

### Network

| # | Command | Expected | Why |
|---|---|---|---|
| N1 | `curl -sS --max-time 5 https://api.github.com \| head -c 50` | **allowed** | github allowlisted |
| N2 | `curl -sS --max-time 5 https://registry.npmjs.org/ \| head -c 50` | **allowed** | npm allowlisted |
| N3 | `curl -sS --max-time 5 https://example.com \| head -c 50` | **blocked (403)** | not allowlisted |
| N4 | `curl -sS --max-time 5 https://evil.example.com \| head -c 50` | **blocked (403)** | not allowlisted |
| N5 | `curl -sS --max-time 5 http://1.1.1.1 \| head -c 50` | **blocked** | raw IPs not allowlisted |
| N6 | `dig +short github.com` | **allowed** | DNS resolution must work for allowlisted domains |
| N7 | `nc -z -G 2 example.com 443` | **blocked** | non-HTTP egress to non-allowlisted host |

### Symlink escape (canonicalization)

| # | Command | Expected |
|---|---|---|
| S1 | `ln -s ~/.ssh /tmp/sshlink 2>/dev/null; cat /tmp/sshlink/id_ed25519` | **blocked** — denyRead must follow symlinks |
| S2 | `ln -s ~/.bashrc ./bashlink && echo x > ./bashlink` | **blocked** — denyWrite must follow symlinks |

---

## Layer 2 — In-process tool guard

These tests run via the **pi tools** (not bash), exercising
`security-guard.ts`. After restarting pi, ask the model to invoke each
tool and check the result against the **Expected** column.

| # | Tool | Args | Expected |
|---|---|---|---|
| T1 | `read` | `~/.ssh/id_ed25519` | blocked, reason cites `denyRead` |
| T2 | `read` | `./SECURITY_PLAN.md` | allowed |
| T3 | `write` | `~/.bashrc.test`, "x" | blocked, reason cites `denyWrite` (basename rule on `.bashrc*`) |
| T4 | `write` | `../escape.txt`, "x" | blocked (escapes cwd; not under any `allowWrite` root) |
| T5 | `edit` | `.env`, … | blocked (basename `.env`) |
| T6 | `fetch_content` | `https://example.com` | blocked, reason cites domain allowlist |
| T7 | `fetch_content` | `https://api.github.com` | allowed |
| T8 | `fetch_content` | `urls: [github.com, evil.example.com]` | blocked on the 2nd entry |
| T9 | `web_search` | (network in headless) | allowed when `subagent.network=allow` (default) |
| T10 | symlink escape via `read` | `read ./link-to-secret/foo` | blocked after canonicalization, even when `foo` doesn't exist |

### Layer 2 unit tests (already passing)

The matcher / URL allowlist / symlink-escape logic has 26 unit tests
covering:

- 13 path-matcher cases (prefix, basename, glob, `~` expansion,
  false-prefix safety like `~/.sshfoo`, recursive `**`, `.` cwd).
- 8 URL allowlist cases (`*.github.com`, deny-wins, false-prefix
  safety like `evil-github.com`, invalid URLs).
- 5 symlink-escape cases (leaf exists, leaf missing, deep nonexistent).

To re-run them after editing `security-guard.ts`:

```bash
node ~/.pi-tmp/symlink-test.mjs   # 5 PASS
node ~/.pi-tmp/url-test.mjs       # 8 PASS
# (path-matcher inline test embedded in the previous session;
#  re-derive from the matchPattern() function in security-guard.ts)
```

### `/security` slash command

Inside pi, run `/security` to print the active Layer 2 policy, the cwd,
`hasUI`, and the resolved `subagent.network` mode.

---

## Layer 3 — Subagent posture

Layer 3 is enabled by setting `policy.subagent.network` in
`sandbox.json`. With the default `"allow"` the tests below pass through;
set `"deny"` or `"research-only"` to exercise the gates.

Spawn a subagent and verify it sees a stricter policy. Run from inside pi:

| # | Setup | Subagent task | Expected |
|---|---|---|---|
| SA1 | Default subagent | `bash: curl https://api.github.com` | **blocked** — non-research subagent has no network |
| SA2 | `librarian` subagent | `fetch_content https://api.github.com` | **allowed** — research-allowlisted |
| SA3 | Default subagent | `read ~/.ssh/id_ed25519` | **blocked** — denyRead inherited |
| SA4 | Default subagent | ambiguous case that would normally prompt | **blocked silently** — `ctx.hasUI === false` ⇒ never prompt |
| SA5 | Subagent with `worktree: true` | `write ../outside-worktree.txt` | **blocked** — `allowWrite` narrowed to worktree |

---

## Layer 4 — Chrome DevTools gate (planned)

| # | Tool | Expected |
|---|---|---|
| B1 | `chrome_devtools_take_snapshot` | allowed (read-only) |
| B2 | `chrome_devtools_screenshot` | allowed (read-only) |
| B3 | `chrome_devtools_list_pages` | allowed (read-only) |
| B4 | `chrome_devtools_navigate_page` (first call this session) | confirm prompt; allow ⇒ allowed for rest of session |
| B5 | `chrome_devtools_evaluate_script` (after B4 confirmed) | allowed (session-confirmed) |
| B6 | `chrome_devtools_navigate_page` from a subagent | **blocked** — no UI to confirm |
| B7 | `pi --allow-browser` then `chrome_devtools_click` | allowed without prompt |

---

## `--yolo` escape hatch

Run from a plain terminal (not from inside pi):

| # | Command | Expected |
|---|---|---|
| Y1 | `pi --yolo`, then `cat ~/.ssh/id_ed25519` | **allowed**, banner `⚠️  YOLO mode` shown |
| Y2 | `pi --yolo`, then `curl https://example.com` | **allowed** |
| Y3 | `pi` (no flags), then any blocked test above | still **blocked** |

---

## Full script

Save as `docs/security/run-tests.sh` and run with `bash run-tests.sh`
*from inside a pi session*. Exit code 0 if all pass.

```bash
#!/usr/bin/env bash
# Pi sandbox smoke tests — Layer 1 only (bash-reachable tests).
# Run from inside a pi bash tool call. The script never aborts on a
# single failure; it tallies pass/fail at the end.

set -u
PASS=0
FAIL=0
TMP="${TMPDIR:-/tmp}"
LOG=$(mktemp -t pi-sectest)
trap 'rm -f "$LOG"' EXIT

# expect_blocked CMD DESC
expect_blocked() {
  local desc=$1; shift
  if "$@" >"$LOG" 2>&1; then
    echo "FAIL: $desc — command unexpectedly succeeded"
    FAIL=$((FAIL+1))
  else
    echo "PASS: $desc"
    PASS=$((PASS+1))
  fi
}

# expect_allowed CMD DESC
expect_allowed() {
  local desc=$1; shift
  if "$@" >"$LOG" 2>&1; then
    echo "PASS: $desc"
    PASS=$((PASS+1))
  else
    echo "FAIL: $desc — exit=$? output=$(head -c 200 "$LOG")"
    FAIL=$((FAIL+1))
  fi
}

echo "=== Layer 1: filesystem reads ==="
# create dummy ssh file outside ~/.ssh that denyRead should not block
expect_blocked "R1 cat ~/.ssh/*"      bash -c "ls ~/.ssh/ 2>&1 | grep -qv 'Operation not permitted' && exit 1 || exit 0"
expect_blocked "R4 cat ~/.netrc"      bash -c "cat ~/.netrc 2>&1 | grep -q 'Operation not permitted' && exit 1; cat ~/.netrc"
expect_allowed "R6 cat cwd file"      bash -c "cat ./SECURITY_PLAN.md >/dev/null"
expect_allowed "R7 cat /etc/hosts"    bash -c "cat /etc/hosts >/dev/null"

echo
echo "=== Layer 1: filesystem writes ==="
expect_blocked "W1 ~/.bashrc.test"    bash -c "echo x > ~/.bashrc.test"
expect_blocked "W3 ./.env.test"       bash -c "echo x > ./.env.test"
expect_blocked "W4 ./test.pem"        bash -c "echo x > ./test.pem"
expect_blocked "W5 ~/.pi/agent/x"     bash -c "echo x > ~/.pi/agent/test.txt"
expect_allowed "W6 cwd write"         bash -c "echo x > ./.smoketest && rm ./.smoketest"
expect_blocked "W7 /tmp/pi-test"      bash -c "echo x > /tmp/pi-smoketest"
expect_allowed "W8 \$TMPDIR write"    bash -c "echo x > \"$TMP/pi-smoketest\" && rm \"$TMP/pi-smoketest\""
expect_allowed "W9 ~/.pi-tmp"         bash -c "mkdir -p ~/.pi-tmp && echo x > ~/.pi-tmp/x && rm ~/.pi-tmp/x"
expect_blocked "W10 /etc write"       bash -c "echo x > /etc/passwd.test"
expect_blocked "W11 ../escape.txt"    bash -c "echo x > ../pi-smoketest-escape"

echo
echo "=== Layer 1: friendly error hint ==="
out=$(bash -c "echo x > /tmp/pi-hinttest" 2>&1 || true)
if echo "$out" | grep -qE 'pi-sandbox|TMPDIR'; then
  echo "PASS: H1 hint surfaced"; PASS=$((PASS+1))
else
  echo "FAIL: H1 hint missing — got: $(echo "$out" | head -c 200)"; FAIL=$((FAIL+1))
fi

echo
echo "=== Layer 1: network ==="
expect_allowed "N1 api.github.com"    bash -c "curl -sS --max-time 5 https://api.github.com -o /dev/null"
expect_allowed "N2 registry.npmjs.org" bash -c "curl -sS --max-time 5 https://registry.npmjs.org/ -o /dev/null"
expect_blocked "N3 example.com"        bash -c "curl -sS --max-time 5 https://example.com -o /dev/null"
expect_blocked "N4 evil.example.com"   bash -c "curl -sS --max-time 5 https://evil.example.com -o /dev/null"
expect_blocked "N5 raw IP 1.1.1.1"     bash -c "curl -sS --max-time 5 http://1.1.1.1 -o /dev/null"

echo
echo "=== Layer 1: symlink escape ==="
expect_blocked "S1 symlink-to-ssh read" bash -c "
  ln -sf ~/.ssh /tmp/pi-sshlink 2>/dev/null;
  cat /tmp/pi-sshlink/id_ed25519 2>&1 | head -c 50;
  test -s /tmp/pi-sshlink/id_ed25519 2>/dev/null
"

echo
echo "------"
echo "PASS=$PASS  FAIL=$FAIL"
test "$FAIL" -eq 0
```

When Layer 2/3/4 ship, extend the script with corresponding sections and
add a top-level `LAYERS=12` toggle so each layer can be run in isolation.

---

## Continuous verification (nice-to-have)

For a CI-like guarantee that future config edits don't regress:

```bash
# Run tests and write a JSON report
bash docs/security/run-tests.sh | tee docs/security/last-run.txt
```

Optional next step: a pre-commit hook that runs the tests if
`sandbox.json` or `sandbox/index.ts` changed in the staged diff.
