/**
 * Pi Security Guard — Layer 2 (in-process tool gate)
 *
 * Hooks `tool_call` for the in-process tools that bash sandbox can't reach
 * (`read`, `write`, `edit`, `fetch_content`, `web_search`,
 * `get_search_content`) and applies the same policy file as the bash
 * sandbox: `~/.pi/agent/extensions/sandbox.json` merged with project-local
 * `<cwd>/.pi/sandbox.json`.
 *
 * Layer 3 (subagent posture) is folded in: when `ctx.hasUI === false` we
 * (a) never prompt, always block on ambiguity, and (b) drop network unless
 * the running agent is in the small research allowlist.
 *
 * Disabled by `--yolo` (single global escape hatch shared with Layer 1).
 *
 * Auto-discovered by pi from `~/.pi/agent/extensions/*.ts`.
 */

import { existsSync, readFileSync, realpathSync, mkdirSync, appendFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, resolve, basename, join } from "node:path";
import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { isToolCallEventType, getAgentDir } from "@mariozechner/pi-coding-agent";

// ---------- Policy ----------

interface Policy {
	enabled: boolean;
	network: { allowedDomains: string[]; deniedDomains: string[] };
	filesystem: {
		denyRead: string[];
		/** Layer 2 ONLY. Files the model's read tool may not access, but subprocesses can (so tools like gh keep working). */
		modelDenyRead?: string[];
		allowWrite: string[];
		denyWrite: string[];
	};
	/**
	 * Additive project-local overrides written by the "always for this cwd"
	 * branch of the ask-tier prompt. Never written from a global config.
	 */
	overrides?: {
		allowRead?: string[];
		allowWrite?: string[];
		allowDomains?: string[];
	};
	/**
	 * Layer 3 — stricter posture for headless pi (`ctx.hasUI === false`,
	 * which covers `-p`, JSON mode, and most subagent transports).
	 * Default: "allow" (no behavior change). Set to "deny" or "research-only"
	 * to opt in.
	 */
	subagent?: { network?: "allow" | "deny" | "research-only" };
}

// Keep in sync with sandbox/index.ts DEFAULT_CONFIG.
const DEFAULT_POLICY: Policy = {
	enabled: true,
	network: {
		allowedDomains: [
			"npmjs.org", "*.npmjs.org",
			"registry.npmjs.org", "registry.yarnpkg.com",
			"pypi.org", "*.pypi.org",
			"github.com", "*.github.com",
			"api.github.com", "raw.githubusercontent.com",
		],
		deniedDomains: [],
	},
	filesystem: {
		denyRead: ["~/.ssh", "~/.aws", "~/.gnupg"],
		allowWrite: [".", "/tmp"],
		denyWrite: [".env", ".env.*", "*.pem", "*.key"],
	},
	subagent: { network: "allow" },
};

function loadPolicy(cwd: string): Policy {
	const paths = [
		`${getAgentDir()}/extensions/sandbox.json`,
		`${cwd}/.pi/sandbox.json`,
	];
	let policy: Policy = JSON.parse(JSON.stringify(DEFAULT_POLICY));
	for (const p of paths) {
		if (!existsSync(p)) continue;
		try {
			const o = JSON.parse(readFileSync(p, "utf-8"));
			if (o.enabled !== undefined) policy.enabled = o.enabled;
			if (o.network) policy.network = { ...policy.network, ...o.network };
			if (o.filesystem) policy.filesystem = { ...policy.filesystem, ...o.filesystem };
			if (o.subagent) policy.subagent = { ...policy.subagent, ...o.subagent };
			if (o.overrides) {
				policy.overrides = {
					allowRead: [...(policy.overrides?.allowRead ?? []), ...(o.overrides.allowRead ?? [])],
					allowWrite: [...(policy.overrides?.allowWrite ?? []), ...(o.overrides.allowWrite ?? [])],
					allowDomains: [...(policy.overrides?.allowDomains ?? []), ...(o.overrides.allowDomains ?? [])],
				};
			}
		} catch (e) {
			console.error(`security-guard: failed to parse ${p}: ${e}`);
		}
	}
	return policy;
}

// ---------- Path matching ----------

function expandHome(p: string): string {
	if (p === "~") return homedir();
	if (p.startsWith("~/")) return `${homedir()}/${p.slice(2)}`;
	return p;
}

/** Convert glob to RegExp. Supports `*`, `**`, `?`. */
function globToRegex(pattern: string): RegExp {
	const re =
		"^" +
		pattern
			.replace(/[.+^${}()|[\]\\]/g, "\\$&")
			.replace(/\*\*/g, "\x00")
			.replace(/\*/g, "[^/]*")
			.replace(/\x00/g, ".*")
			.replace(/\?/g, "[^/]") +
		"$";
	return new RegExp(re, process.platform === "darwin" ? "i" : "");
}

/**
 * Canonicalize a path for matching.
 *
 * - Resolved against cwd if relative.
 * - Walks up to the deepest existing ancestor and realpaths *that*, so
 *   symlinks in the path prefix are followed even when the leaf (or any
 *   intermediate) doesn't exist yet. Defeats the
 *   `cwd/symlink-to-ssh/anything` escape regardless of whether `anything`
 *   exists.
 */
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

/**
 * Match an absolute path against a policy pattern.
 *
 *   - Patterns starting with `/` or `~` → full-path match (prefix or glob).
 *   - `.` → matches anything under cwd (handled by callers via roots).
 *   - Other (`.env`, `*.pem`) → basename match against the file's basename.
 */
function matchPattern(absPath: string, pattern: string, cwd: string): boolean {
	const p = expandHome(pattern);
	if (p === ".") {
		const cwdReal = canonicalize(cwd, cwd);
		return absPath === cwdReal || absPath.startsWith(`${cwdReal}/`);
	}
	if (p.startsWith("/")) {
		if (p.includes("*")) return globToRegex(p).test(absPath);
		return absPath === p || absPath.startsWith(`${p}/`);
	}
	// basename pattern
	const base = basename(absPath);
	if (p.includes("*")) return globToRegex(p).test(base);
	return base === p;
}

// Hardcoded absolute-deny tier (per PLAN-ask-tier-ux.md OQ#5).
// Bypassing requires typing "i understand" verbatim; "always" is forbidden.
const ABSOLUTE_DENY_PATTERNS = ["~/.ssh", "~/.gnupg", "~/.aws", "*.pem", "*.key"];

function isAbsoluteDeny(absPath: string, cwd: string): string | null {
	for (const pat of ABSOLUTE_DENY_PATTERNS) {
		if (matchPattern(absPath, pat, cwd)) return pat;
	}
	return null;
}

function isOverridden(absPath: string, cwd: string, list: string[] | undefined): boolean {
	if (!list || list.length === 0) return false;
	return list.some((pat) => matchPattern(absPath, pat, cwd));
}

function isDeniedRead(rawPath: string, cwd: string, policy: Policy): string | null {
	const abs = canonicalize(rawPath, cwd);
	if (isOverridden(abs, cwd, policy.overrides?.allowRead)) return null;
	for (const pat of policy.filesystem.modelDenyRead ?? []) {
		if (matchPattern(abs, pat, cwd)) return `modelDenyRead matched "${pat}" → ${abs}`;
	}
	for (const pat of policy.filesystem.denyRead) {
		if (matchPattern(abs, pat, cwd)) return `denyRead matched "${pat}" → ${abs}`;
	}
	return null;
}

function isDeniedWrite(rawPath: string, cwd: string, policy: Policy): string | null {
	const abs = canonicalize(rawPath, cwd);
	if (isOverridden(abs, cwd, policy.overrides?.allowWrite)) return null;
	for (const pat of policy.filesystem.denyWrite) {
		if (matchPattern(abs, pat, cwd)) return `denyWrite matched "${pat}" → ${abs}`;
	}
	const allowed = policy.filesystem.allowWrite.some((pat) => matchPattern(abs, pat, cwd));
	if (!allowed) return `not under any allowWrite root → ${abs}`;
	return null;
}

// ---------- Domain matching ----------

function hostnameOf(url: string): string | null {
	try {
		return new URL(url).hostname.toLowerCase();
	} catch {
		return null;
	}
}

function domainMatches(host: string, pattern: string): boolean {
	const p = pattern.toLowerCase();
	if (p.startsWith("*.")) {
		const suffix = p.slice(1); // ".npmjs.org"
		return host === p.slice(2) || host.endsWith(suffix);
	}
	return host === p;
}

function isAllowedUrl(url: string, policy: Policy): string | null {
	const host = hostnameOf(url);
	if (!host) return `not a valid URL: ${url}`;
	if (policy.network.deniedDomains.some((p) => domainMatches(host, p)))
		return `denied domain: ${host}`;
	if ((policy.overrides?.allowDomains ?? []).some((p) => domainMatches(host, p))) return null;
	if (policy.network.allowedDomains.length === 0) return null;
	if (policy.network.allowedDomains.some((p) => domainMatches(host, p))) return null;
	return `domain not in allowlist: ${host}`;
}

// ---------- Audit log ----------

const AUDIT_PATH = `${getAgentDir()}/audit.log`;

function audit(entry: Record<string, unknown>): void {
	try {
		appendFileSync(AUDIT_PATH, `${JSON.stringify({ ts: new Date().toISOString(), ...entry })}\n`);
	} catch {
		/* best-effort */
	}
}

// ---------- Project-local persistence ("always for this cwd") ----------

type OverrideKind = "allowRead" | "allowWrite" | "allowDomains";

function persistAlways(cwd: string, kind: OverrideKind, value: string): string {
	const dir = join(cwd, ".pi");
	const path = join(dir, "sandbox.json");
	let existing: { overrides?: Record<OverrideKind, string[]> } = {};
	if (existsSync(path)) {
		try {
			existing = JSON.parse(readFileSync(path, "utf-8"));
		} catch {
			/* overwrite a corrupt project-local config */
		}
	}
	const overrides = (existing.overrides ?? {}) as Record<OverrideKind, string[]>;
	const list = (overrides[kind] ?? []) as string[];
	if (!list.includes(value)) list.push(value);
	overrides[kind] = list;
	existing.overrides = overrides;
	mkdirSync(dir, { recursive: true });
	writeFileSync(path, `${JSON.stringify(existing, null, 2)}\n`);
	return path;
}

// ---------- Ask-tier prompt ----------

type AskKind = { layer: 2; tool: string; subject: string; reason: string; overrideKind: OverrideKind; overrideValue: string };
type Decision = "yes" | "no" | "always";
type UICtx = {
	cwd: string;
	hasUI?: boolean;
	ui: {
		select: (t: string, o: string[], op?: { timeout?: number }) => Promise<string | undefined>;
		input: (t: string, p?: string, op?: { timeout?: number }) => Promise<string | undefined>;
		notify: (m: string, l?: string) => void;
	};
};

async function askDecision(ctx: UICtx, k: AskKind, absoluteDenyPattern: string | null): Promise<Decision> {
	if (ctx.hasUI === false) return "no"; // subagents, -p, JSON mode
	if (absoluteDenyPattern) {
		const banner = `⚠️  HIGH-RISK BLOCK — Layer 2\n\nTool:    ${k.tool}\nSubject: ${k.subject}\nReason:  ${k.reason}\nMatched absolute-deny tier: ${absoluteDenyPattern}\n\nAccess to credential material is almost always exfiltration.\nType "i understand" exactly to allow this ONE call. "always" is not available for this tier.`;
		const typed = await ctx.ui.input(banner, "i understand", { timeout: 60_000 });
		return typed === "i understand" ? "yes" : "no";
	}
	const title = `Layer 2 block: ${k.tool}\n\nSubject: ${k.subject}\nReason:  ${k.reason}\n\nAllow?`;
	const options = [
		"yes — this once",
		"no  — block (default)",
		"always for this cwd — write .pi/sandbox.json",
	];
	const chosen = await ctx.ui.select(title, options, { timeout: 60_000 });
	if (chosen === options[0]) return "yes";
	if (chosen === options[2]) return "always";
	return "no";
}

async function askOrBlock(ctx: UICtx, k: AskKind, absoluteDenyPattern: string | null): Promise<{ block: true; reason: string } | null> {
	const decision = await askDecision(ctx, k, absoluteDenyPattern);
	if (decision === "no") {
		audit({ layer: 2, tool: k.tool, subject: k.subject, reason: k.reason, decision: "no", cwd: ctx.cwd });
		return { block: true, reason: `${k.tool} blocked: ${k.reason}` };
	}
	if (decision === "always") {
		if (absoluteDenyPattern) {
			audit({ layer: 2, tool: k.tool, subject: k.subject, reason: k.reason, decision: "no", note: "always-refused-for-absolute-deny", cwd: ctx.cwd });
			return { block: true, reason: `${k.tool} blocked: ${k.reason}` };
		}
		try {
			const path = persistAlways(ctx.cwd, k.overrideKind, k.overrideValue);
			audit({ layer: 2, tool: k.tool, subject: k.subject, reason: k.reason, decision: "always", cwd: ctx.cwd, persisted_to: path, override: { [k.overrideKind]: k.overrideValue } });
			ctx.ui.notify(`security-guard: persisted override → ${path}`, "warning");
		} catch (e) {
			audit({ layer: 2, tool: k.tool, subject: k.subject, reason: k.reason, decision: "yes", note: `always-persist-failed: ${e}`, cwd: ctx.cwd });
			ctx.ui.notify(`security-guard: could not persist override (${e}); allowing this call only`, "warning");
		}
		return null;
	}
	audit({ layer: 2, tool: k.tool, subject: k.subject, reason: k.reason, decision: "yes", cwd: ctx.cwd });
	return null;
}

// ---------- Subagent posture (Layer 3) ----------

const RESEARCH_AGENTS = new Set(["librarian", "scout", "researcher"]);

/**
 * Decide if a network-bound tool call should be blocked under the current
 * subagent posture. Returns a reason string when blocked, or null to allow.
 *
 * Heuristic for "is research agent": pi doesn't expose an agent name on
 * `ctx`, so we look at the most recent assistant text in the session for a
 * known research-agent marker. Best-effort — v2 should plumb agent
 * identity through `ctx`.
 */
function subagentNetworkBlock(ctx: { hasUI?: boolean; sessionManager?: unknown }, policy: Policy): string | null {
	if (ctx.hasUI !== false) return null; // only applies headless
	const mode = policy.subagent?.network ?? "allow";
	if (mode === "allow") return null;
	if (mode === "deny") return "subagent network access denied (policy: subagent.network=deny)";
	if (mode === "research-only") {
		// Best-effort: scan recent session for a known research-agent name.
		const sm = ctx.sessionManager as { getBranch?: () => Array<{ type: string; text?: string }> } | undefined;
		const branch = sm?.getBranch?.() ?? [];
		const joined = branch
			.slice(-10)
			.map((e) => (typeof e.text === "string" ? e.text : ""))
			.join(" ")
			.toLowerCase();
		for (const a of RESEARCH_AGENTS) if (joined.includes(a)) return null;
		return "subagent network access denied (policy: subagent.network=research-only)";
	}
	return null;
}

// ---------- Extension entry ----------

export default function (pi: ExtensionAPI) {
	let active = false;

	pi.on("session_start", (_event, ctx) => {
		const yolo = (pi.getFlag?.("yolo") as boolean) || (pi.getFlag?.("no-sandbox") as boolean);
		if (yolo) {
			active = false;
			ctx.ui.notify("⚠️  security-guard (Layer 2) disabled: --yolo", "warning");
			return;
		}
		const policy = loadPolicy(ctx.cwd);
		if (!policy.enabled) {
			active = false;
			ctx.ui.notify("security-guard (Layer 2) disabled: enabled=false in sandbox.json", "info");
			return;
		}
		active = true;
		ctx.ui.notify("🔒 security-guard (Layer 2) active", "info");
	});

	pi.on("tool_call", async (event, ctx) => {
		if (!active) return;
		const policy = loadPolicy(ctx.cwd);

		// --- Path-based gates (with ask-tier prompt) ---
		if (isToolCallEventType("read", event)) {
			const reason = isDeniedRead(event.input.path, ctx.cwd, policy);
			if (reason) {
				const abs = canonicalize(event.input.path, ctx.cwd);
				const result = await askOrBlock(ctx as unknown as UICtx, { layer: 2, tool: "read", subject: abs, reason, overrideKind: "allowRead", overrideValue: abs }, isAbsoluteDeny(abs, ctx.cwd));
				if (result) return result;
			}
		}
		if (isToolCallEventType("write", event)) {
			const reason = isDeniedWrite(event.input.path, ctx.cwd, policy);
			if (reason) {
				const abs = canonicalize(event.input.path, ctx.cwd);
				const result = await askOrBlock(ctx as unknown as UICtx, { layer: 2, tool: "write", subject: abs, reason, overrideKind: "allowWrite", overrideValue: abs }, isAbsoluteDeny(abs, ctx.cwd));
				if (result) return result;
			}
		}
		if (isToolCallEventType("edit", event)) {
			const reason = isDeniedWrite(event.input.path, ctx.cwd, policy);
			if (reason) {
				const abs = canonicalize(event.input.path, ctx.cwd);
				const result = await askOrBlock(ctx as unknown as UICtx, { layer: 2, tool: "edit", subject: abs, reason, overrideKind: "allowWrite", overrideValue: abs }, isAbsoluteDeny(abs, ctx.cwd));
				if (result) return result;
			}
		}

		// --- URL/domain gates (best-effort by tool name; tools are extension-defined) ---
		const input = event.input as Record<string, unknown> | undefined;
		const collectUrls = (): string[] => {
			if (!input) return [];
			const urls: string[] = [];
			if (typeof input.url === "string") urls.push(input.url);
			if (Array.isArray(input.urls)) {
				for (const u of input.urls) if (typeof u === "string") urls.push(u);
			}
			return urls;
		};

		if (event.toolName === "fetch_content" || event.toolName === "get_search_content") {
			const saReason = subagentNetworkBlock(ctx as { hasUI?: boolean; sessionManager?: unknown }, policy);
			if (saReason) return { block: true, reason: saReason };
			for (const u of collectUrls()) {
				const reason = isAllowedUrl(u, policy);
				if (!reason) continue;
				const host = hostnameOf(u) ?? u;
				const result = await askOrBlock(ctx as unknown as UICtx, { layer: 2, tool: event.toolName, subject: u, reason, overrideKind: "allowDomains", overrideValue: host }, null);
				if (result) return result;
			}
		}

		if (event.toolName === "web_search") {
			const saReason = subagentNetworkBlock(ctx as { hasUI?: boolean; sessionManager?: unknown }, policy);
			if (saReason) return { block: true, reason: saReason };
			// web_search itself goes to the search provider (out of scope for v1
			// allowlist). The follow-on fetch_content for individual results is
			// the catchable surface.
		}
	});

	pi.registerCommand?.("security", {
		description: "Show Layer 2 (security-guard) policy and status",
		handler: async (_args, ctx) => {
			if (!active) {
				ctx.ui.notify("security-guard: inactive (yolo or disabled)", "info");
				return;
			}
			const policy = loadPolicy(ctx.cwd);
			const overrides = policy.overrides ?? {};
			const lines = [
				"Security Guard (Layer 2):",
				"",
				`  cwd:               ${ctx.cwd}`,
				`  hasUI:             ${(ctx as { hasUI?: boolean }).hasUI !== false}`,
				`  subagent.network:  ${policy.subagent?.network ?? "allow"}`,
				"",
				"Filesystem:",
				`  denyRead:    ${policy.filesystem.denyRead.join(", ") || "(none)"}`,
				`  allowWrite:  ${policy.filesystem.allowWrite.join(", ") || "(none)"}`,
				`  denyWrite:   ${policy.filesystem.denyWrite.join(", ") || "(none)"}`,
				"",
				"Network (URL tools):",
				`  allowed:     ${policy.network.allowedDomains.join(", ") || "(none)"}`,
				`  denied:      ${policy.network.deniedDomains.join(", ") || "(none)"}`,
				"",
				"Project-local overrides (<cwd>/.pi/sandbox.json `overrides`):",
				`  allowRead:    ${(overrides.allowRead ?? []).join(", ") || "(none)"}`,
				`  allowWrite:   ${(overrides.allowWrite ?? []).join(", ") || "(none)"}`,
				`  allowDomains: ${(overrides.allowDomains ?? []).join(", ") || "(none)"}`,
			];
			try {
				const tail = readFileSync(AUDIT_PATH, "utf-8").trim().split("\n").slice(-10);
				if (tail.length && tail[0]) {
					lines.push("", "Recent audit (last 10):");
					for (const l of tail) lines.push(`  ${l}`);
				}
			} catch {
				/* no audit log yet */
			}
			ctx.ui.notify(lines.join("\n"), "info");
		},
	});
}
