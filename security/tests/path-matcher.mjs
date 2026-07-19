// Layer 2 — path matcher unit tests
// Mirrors the matchPattern() / canonicalize() logic from
// ~/.pi/agent/extensions/security-guard.ts. If you change the matcher
// there, update this file too (or extract into a shared module — TODO).
import { realpathSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, resolve, basename } from "node:path";

function expandHome(p) { if (p === "~") return homedir(); if (p.startsWith("~/")) return homedir() + "/" + p.slice(2); return p; }
function globToRegex(pattern) {
	const re = "^" + pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*\*/g, "\x00").replace(/\*/g, "[^/]*").replace(/\x00/g, ".*").replace(/\?/g, "[^/]") + "$";
	return new RegExp(re, "i");
}
function canonicalize(p, cwd) {
	const abs = isAbsolute(p) ? p : resolve(cwd, p);
	const trail = [];
	let cur = abs;
	while (true) {
		try { const real = realpathSync(cur); return trail.length ? real + "/" + trail.slice().reverse().join("/") : real; }
		catch { const parent = dirname(cur); if (parent === cur) return abs; trail.push(basename(cur)); cur = parent; }
	}
}
function matchPattern(absPath, pattern, cwd) {
	const p = expandHome(pattern);
	if (p === ".") { const c = canonicalize(cwd, cwd); return absPath === c || absPath.startsWith(c + "/"); }
	if (p.startsWith("/")) { if (p.includes("*")) return globToRegex(p).test(absPath); return absPath === p || absPath.startsWith(p + "/"); }
	const base = basename(absPath);
	if (p.includes("*")) return globToRegex(p).test(base);
	return base === p;
}

const home = homedir();
const cwd = home + "/.pi/playground";
const cases = [
	[`${home}/.ssh/id_rsa`,                                        "~/.ssh",          true,  "denyRead ~/.ssh hits child"],
	[`${home}/.ssh`,                                               "~/.ssh",          true,  "denyRead ~/.ssh hits self"],
	[`${home}/.sshfoo`,                                            "~/.ssh",          false, "denyRead ~/.ssh no false-prefix"],
	[`${home}/.bashrc.test`,                                       "~/.bashrc",       false, "~/.bashrc is exact only (basename rule then catches via not-in-allowWrite)"],
	[`${home}/foo.pem`,                                            "*.pem",           true,  "basename glob *.pem"],
	[`${home}/.env.local`,                                         ".env.*",          true,  "basename glob .env.*"],
	[`${home}/.env`,                                               ".env",            true,  "basename exact .env"],
	[`${home}/.pi/agent/extensions/foo.ts`,                        "~/.pi/agent/**",  true,  "recursive glob"],
	[`${home}/.pi/playground/foo.ts`,                              "~/.pi/agent/**",  false, "recursive glob does not bleed"],
	[`${home}/.pi/playground/x.ts`,                                ".",               true,  ". allowWrite covers cwd descendants"],
	["/etc/passwd",                                                ".",               false, ". does not cover /etc"],
	["/private/tmp/pi-502/foo",                                    "/private/tmp/pi-502", true,  "allowWrite tmp dir"],
	["/private/tmp/something-else",                                "/private/tmp/pi-502", false, "allowWrite tmp does not bleed"],
];
let pass = 0, fail = 0;
for (const [p, pat, exp, label] of cases) {
	const got = matchPattern(p, pat, cwd);
	const ok = got === exp;
	console.log((ok ? "PASS" : "FAIL") + ": " + label + "  (" + p + " vs " + pat + " → " + got + ", exp " + exp + ")");
	ok ? pass++ : fail++;
}
console.log("---", "PASS=" + pass, "FAIL=" + fail);
process.exit(fail ? 1 : 0);
