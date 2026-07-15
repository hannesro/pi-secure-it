#!/usr/bin/env bash
# One-stop security check.
#
#   ./security/check.sh        — run all tests, regenerate SECURITY.md, print summary
#   ./security/check.sh tests  — run tests only
#   ./security/check.sh render — regenerate SECURITY.md only
#
# Tests are derived from security/manifest.json. Edit the manifest to
# add/remove tests; this script picks them up automatically.

set -uo pipefail
cd "$(dirname "$0")/.."

TMPDIR="${TMPDIR:-/private/tmp/pi-$(id -u)/}"
mkdir -p "$TMPDIR" 2>/dev/null || true
out="$TMPDIR/sec-$$-out"

mode="${1:-all}"
manifest="security/manifest.json"
pass=0; fail=0; skipped=0
results=()

run_tests() {
	# Extract { id, command, expected } from manifest.layers[*].tests[*]
	# Skip tests whose expected starts with "manual".
	local i=0
	while IFS=$'\t' read -r id cmd expected; do
		i=$((i+1))
		if [[ "$expected" == manual* ]]; then
			skipped=$((skipped+1))
			results+=("SKIP  $id  ($expected)")
			continue
		fi
		if eval "$cmd" >"$out" 2>&1; then
			pass=$((pass+1))
			summary=$(grep -E "^---|PASS=" "$out" | tail -1)
			results+=("PASS  $id  $summary")
		else
			fail=$((fail+1))
			summary=$(tail -3 "$out" | tr '\n' ' ')
			results+=("FAIL  $id  $summary")
		fi
		rm -f "$out"
	done < <(node -e "
		const m = JSON.parse(require('fs').readFileSync('$manifest','utf8'));
		for (const L of m.layers)
			for (const t of (L.tests||[]))
				console.log([t.id, t.command, t.expected].join('\t'));
	")
}

case "$mode" in
	all|tests)
		run_tests
		;;
esac

case "$mode" in
	all|render)
		echo
		node security/render.mjs
		;;
esac

if [[ "$mode" != "render" ]]; then
	echo
	echo "── Test results ──────────────────────────────────────────────"
	for r in "${results[@]}"; do echo "  $r"; done
	echo "──────────────────────────────────────────────────────────────"
	echo "  PASS=$pass  FAIL=$fail  SKIP=$skipped"
	echo
	[[ $fail -eq 0 ]] && echo "✓ all tests pass" || { echo "✗ $fail test(s) failed"; exit 1; }
fi
