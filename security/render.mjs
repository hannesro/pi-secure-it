#!/usr/bin/env node
// Reads security/manifest.json and renders SECURITY.md (current-state overview).
// Also checks that source files referenced by the manifest actually exist.
// Run via security/check.sh — DO NOT edit SECURITY.md by hand.

import { readFileSync, writeFileSync, existsSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, "..");
const manifest = JSON.parse(readFileSync(resolve(__dirname, "manifest.json"), "utf8"));

const expandHome = (p) => p.replace(/^~/, homedir());
const fileStatus = (p) => {
	const abs = expandHome(p);
	if (!existsSync(abs)) return { ok: false, note: "MISSING" };
	const s = statSync(abs);
	const mtime = s.mtime.toISOString().slice(0, 10);
	const lines = s.isFile() ? readFileSync(abs, "utf8").split("\n").length : null;
	return { ok: true, note: lines !== null ? `${lines} lines, mtime ${mtime}` : `dir, mtime ${mtime}` };
};

const STATUS_GLYPH = {
	"shipped": "✅",
	"shipped-opt-in": "🟢",
	"in-progress": "🟡",
	"not-started": "⬜",
	"deprecated": "⚠️",
};

const out = [];
out.push("# Security — current state");
out.push("");
out.push("> **Auto-generated** by `security/render.mjs` from `security/manifest.json`. Do not edit by hand. Run `./security/check.sh` after changing the manifest or any source file.");
out.push("");
out.push(`Generated: ${new Date().toISOString()}`);
out.push("");
out.push("## At a glance");
out.push("");
out.push("| Layer | Status | Source files | Tests |");
out.push("|---|---|---|---|");
for (const L of manifest.layers) {
	const glyph = STATUS_GLYPH[L.status] ?? "❓";
	const files = L.sourceFiles.length ? L.sourceFiles.map((f) => {
		const fs = fileStatus(f);
		return fs.ok ? `\`${f}\`` : `❌ \`${f}\``;
	}).join("<br>") : "—";
	const tests = L.tests.length ? L.tests.map((t) => `\`${t.id}\``).join(", ") : "—";
	out.push(`| **${L.id}** ${L.name} | ${glyph} ${L.status} | ${files} | ${tests} |`);
}
out.push("");

out.push("## UX polish");
out.push("");
out.push("| ID | Status | What |");
out.push("|---|---|---|");
for (const u of manifest.uxPolish) {
	out.push(`| \`${u.id}\` | ${STATUS_GLYPH[u.status] ?? "❓"} ${u.status} | ${u.what} |`);
}
out.push("");

out.push("## Layer detail");
out.push("");
for (const L of manifest.layers) {
	const glyph = STATUS_GLYPH[L.status] ?? "❓";
	out.push(`### ${L.id} — ${L.name}  ${glyph} ${L.status}`);
	out.push("");
	out.push(L.purpose);
	out.push("");
	if (L.sourceFiles.length) {
		out.push("**Source files**");
		out.push("");
		for (const f of L.sourceFiles) {
			const fs = fileStatus(f);
			out.push(`- ${fs.ok ? "✓" : "❌"} \`${f}\` — ${fs.note}`);
		}
		out.push("");
	}
	if (L.config) {
		out.push("**Config**");
		out.push("");
		out.push(`- Key: \`${L.config.key}\``);
		out.push(`- Values: ${L.config.values.map((v) => `\`${v}\``).join(", ")}`);
		out.push(`- Default: \`${L.config.default}\``);
		if (L.config.note) out.push(`- Note: ${L.config.note}`);
		out.push("");
	}
	if (L.tests.length) {
		out.push("**Tests**");
		out.push("");
		for (const t of L.tests) {
			out.push(`- \`${t.id}\` — \`${t.command}\` → expects ${t.expected}`);
		}
		out.push("");
	}
	if (L.knownGaps.length) {
		out.push("**Known gaps / accepted risks**");
		out.push("");
		for (const g of L.knownGaps) out.push(`- ${g}`);
		out.push("");
	}
}

out.push("## Policy files");
out.push("");
out.push(`- Global: \`${manifest.policyFile}\` — ${fileStatus(manifest.policyFile).note}`);
out.push(`- Project override: \`${manifest.projectPolicyFile}\` (per-cwd; merges over global)`);
out.push(`- Escape hatch: \`${manifest.yoloFlag}\``);
out.push("");

out.push("## Where to find things");
out.push("");
out.push("| File | Role |");
out.push("|---|---|");
for (const d of manifest.docs) out.push(`| \`${d.path}\` | ${d.role} |`);
out.push("");

const target = resolve(root, "SECURITY.md");
writeFileSync(target, out.join("\n"));
console.log(`Wrote ${target} (${out.length} lines)`);
