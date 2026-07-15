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
# ls of a denied dir prints "Operation not permitted" but exit code varies;
# check the *output* contains the sandbox signature instead of trusting $?
out=$(ls ~/.ssh/ 2>&1 || true)
if echo "$out" | grep -qi 'operation not permitted'; then
  echo "PASS: R1 ls ~/.ssh blocked"; PASS=$((PASS+1))
else
  echo "FAIL: R1 ls ~/.ssh — sandbox signature missing, got: $(echo "$out" | head -c 120)"
  FAIL=$((FAIL+1))
fi
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
# The hint is emitted once per pi bash-tool invocation (on close of the
# wrapped process), not per inner `bash -c`. So we can't test it from
# inside this script — the script itself is one wrapped invocation, and
# the hint only fires when the script exits, after our capture has run.
#
# To verify the hint manually, run this directly via pi:
#     echo x > /tmp/pi-hinttest 2>&1
# Expected: "Operation not permitted" followed by a "💡 pi-sandbox" hint.
echo "SKIP:  H1 hint — verify manually (see comment in run-tests.sh)"

echo
echo "=== Layer 1: network ==="
expect_allowed "N1 api.github.com"    bash -c "curl -sS --max-time 5 https://api.github.com -o /dev/null"
expect_allowed "N2 registry.npmjs.org" bash -c "curl -sS --max-time 5 https://registry.npmjs.org/ -o /dev/null"
expect_blocked "N3 example.com"        bash -c "curl -sS --max-time 5 https://example.com -o /dev/null"
expect_blocked "N4 evil.example.com"   bash -c "curl -sS --max-time 5 https://evil.example.com -o /dev/null"
# N5 is a known gap (raw-IP bypass) — see tradeoffs.md. Reported as XFAIL.
if bash -c "curl -sS --max-time 5 http://1.1.1.1 -o /dev/null" >/dev/null 2>&1; then
  echo "XFAIL: N5 raw IP 1.1.1.1 — known gap, see tradeoffs.md"
else
  echo "PASS:  N5 raw IP 1.1.1.1 (unexpectedly blocked — nice!)"; PASS=$((PASS+1))
fi

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
