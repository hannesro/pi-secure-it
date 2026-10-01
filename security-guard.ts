/**
 * Pi Security Guard — Layer 2 (in-process tool gate)
 *
 * Hooks `tool_call` for the in-process tools that bash sandbox can't reach
 * (`read`, `grep`, `find`, `ls`, `write`, `edit`, `fetch_content`,
 * `web_search`, `get_search_content`) and applies the same policy file as
 * the bash sandbox: `~/.pi/agent/extensions/sandbox.json` merged with
 * project-local `<cwd>/.pi/sandbox.json`. Hooks `tool_result` to drop grep
 * output lines from denied files beneath an allowed search root.
 *
 * Layer 3 (subagent posture) is folded in: when `ctx.hasUI === false` we
 * (a) never prompt, always block on ambiguity, and (b) drop network unless
 * the running agent is in the small research allowlist.
 *
 * Disabled by `--yolo` (single global escape hatch shared with Layer 1).
 *
 * Auto-discovered by pi from `~/.pi/agent/extensions/*.ts`.
 */

import { existsSync, readFileSync, realpathSync, mkdirSync, appendFileSync, writeFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, resolve, basename, join } from "node:path";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { isToolCallEventType, getAgentDir } from "@earendil-works/pi-coding-agent";
import { type Layer2Mode, filterGrepOutput, layer2Mode, policyFileError, readPolicyForUpdate } from "./lib/guard-lib";

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
	/**
	 * Layer 2 role (ADR-011). "guard": decide and prompt for every policy miss.
	 * "floor": run beside @gotgenes/pi-permission-system, which decides paths;
	 * Layer 2 keeps only the absolute-deny floor, the grep output filter and the
	 * domain allowlist, and never prompts for ordinary misses. Unset: "floor"
	 * when pi-permission-system is active for the session, else "guard".
	 */
	layer2?: Layer2Mode;
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
			if (o.layer2 === "guard" || o.layer2 === "floor") policy.layer2 = o.layer2;
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
// Allowing one call takes two select steps that default to block (ADR-009); "always" is forbidden.
// pi's own auth.json holds the provider OAuth tokens and API keys pi runs on.
const ABSOLUTE_DENY_PATTERNS = ["~/.ssh", "~/.gnupg", "~/.aws", "*.pem", "*.key", `${getAgentDir()}/auth.json`];

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

// The absolute-deny tier denies on its own. Before, it only chose the prompt
// shown after denyRead/denyWrite had already matched, so `*.pem`, `*.key`,
// `~/.aws` and auth.json stayed readable under any policy that did not list
// them. Checked before overrides: "always" is never offered for this tier.
function isDeniedRead(rawPath: string, cwd: string, policy: Policy): string | null {
	const abs = canonicalize(rawPath, cwd);
	const absolute = isAbsoluteDeny(abs, cwd);
	if (absolute) return `absolute-deny matched "${absolute}" → ${abs}`;
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
	const absolute = isAbsoluteDeny(abs, cwd);
	if (absolute) return `absolute-deny matched "${absolute}" → ${abs}`;
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

// ---------- Persistence ("always" tiers) ----------

type OverrideKind = "allowRead" | "allowWrite" | "allowDomains";
type Scope = "cwd" | "global";

function persistOverride(scope: Scope, cwd: string, kind: OverrideKind, value: string): string {
	const { dir, path } =
		scope === "cwd"
			? { dir: join(cwd, ".pi"), path: join(cwd, ".pi", "sandbox.json") }
			: { dir: join(getAgentDir(), "extensions"), path: join(getAgentDir(), "extensions", "sandbox.json") };
	// Throws on an unparseable file: never overwrite a hand-written policy we could not read.
	const existing = readPolicyForUpdate(path) as Record<string, unknown> & { overrides?: Record<OverrideKind, string[]> };
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
type Decision = "yes" | "no" | "session" | "session-folder" | "always-cwd" | "always-global" | "always-cwd-folder" | "always-global-folder";
type UICtx = {
	cwd: string;
	hasUI?: boolean;
	ui: {
		select: (t: string, o: string[], op?: { timeout?: number }) => Promise<string | undefined>;
		input: (t: string, p?: string, op?: { timeout?: number }) => Promise<string | undefined>;
		notify: (m: string, l?: string) => void;
	};
};

// ---------- Layer 2 role and session grants (ADR-010, ADR-011) ----------

/**
 * Grants from "yes — for this session" in guard mode. In memory only, cleared
 * on session_start, never written to sandbox.json, never consulted for the
 * absolute-deny tier.
 */
const sessionGrants: Array<{ kind: OverrideKind; value: string }> = [];

function sessionGranted(k: AskKind, cwd: string): string | null {
	for (const g of sessionGrants) {
		if (g.kind !== k.overrideKind) continue;
		const hit = g.kind === "allowDomains" ? domainMatches(k.overrideValue, g.value) : matchPattern(k.subject, g.value, cwd);
		if (hit) return g.value;
	}
	return null;
}

async function askDecision(ctx: UICtx, k: AskKind, absoluteDenyPattern: string | null): Promise<Decision> {
	if (ctx.hasUI === false) return "no"; // subagents, -p, JSON mode
	if (absoluteDenyPattern) {
		// Two deliberate steps (ADR-009). Both are select menus whose first,
		// pre-selected option blocks, so Enter-Enter can never approve. pi's
		// ctx.ui.confirm is not used: it lists "Yes" first and pre-selects it.
		const banner = `⚠️  HIGH-RISK BLOCK — Layer 2\n\nTool:    ${k.tool}\nSubject: ${k.subject}\nReason:  ${k.reason}\nMatched absolute-deny tier: ${absoluteDenyPattern}\n\nAccess to credential material is almost always exfiltration.\n"always" is not available for this tier.`;
		const step1 = ["no  — block (default)", "allow this ONE call"];
		if ((await ctx.ui.select(banner, step1, { timeout: 60_000 })) !== step1[1]) return "no";
		const step2 = ["No  — keep it blocked (default)", "Yes — allow this ONE call"];
		const check = `Really allow ${k.tool} on credential material?\n\n${k.subject}`;
		return (await ctx.ui.select(check, step2, { timeout: 30_000 })) === step2[1] ? "yes" : "no";
	}
	const isFileKind = k.overrideKind === "allowRead" || k.overrideKind === "allowWrite";
	const parentDir = isFileKind ? dirname(k.overrideValue) : null;
	const title = `Layer 2 block: ${k.tool}\n\nSubject: ${k.subject}\nReason:  ${k.reason}\n\nAllow?`;
	// "no" first and pre-selected: Enter alone blocks (ADR-010).
	const options: string[] = ["no  — block (default)", "yes — this once", "yes — for this session (not saved)"];
	if (isFileKind) options.push(`yes — for this session: parent folder ${parentDir} (not saved)`);
	options.push("always for CURRENT project — whitelist this file (.pi/sandbox.json)");
	if (isFileKind) options.push(`always for CURRENT project — whitelist parent folder ${parentDir} (.pi/sandbox.json)`);
	options.push("always for ALL projects — whitelist this file (~/.pi/agent/extensions/sandbox.json)");
	if (isFileKind) options.push(`always for ALL projects — whitelist parent folder ${parentDir} (~/.pi/agent/extensions/sandbox.json)`);
	const chosen = await ctx.ui.select(title, options, { timeout: 60_000 });
	if (!chosen || chosen === options[0]) return "no";
	if (chosen === options[1]) return "yes";
	if (chosen.startsWith("yes — for this session")) return chosen.includes("parent folder") ? "session-folder" : "session";
	if (chosen.startsWith("always for CURRENT project")) return chosen.includes("parent folder") ? "always-cwd-folder" : "always-cwd";
	if (chosen.startsWith("always for ALL projects")) return chosen.includes("parent folder") ? "always-global-folder" : "always-global";
	return "no";
}

async function askOrBlock(ctx: UICtx, k: AskKind, absoluteDenyPattern: string | null, mode: Layer2Mode): Promise<{ block: true; reason: string } | null> {
	// The absolute-deny tier skips floor mode and session grants: it always goes
	// to the human two-step menu, and is blocked headless.
	if (!absoluteDenyPattern) {
		if (mode === "floor") {
			// pi-permission-system decides paths. Domains it cannot see (it gates
			// web tools by name only), so the allowlist still holds, without a prompt.
			if (k.overrideKind !== "allowDomains") return null;
			audit({ layer: 2, tool: k.tool, subject: k.subject, reason: k.reason, decision: "floor-deny", cwd: ctx.cwd });
			return { block: true, reason: `${k.tool} blocked: ${k.reason}. The user can allow it by adding the domain to network.allowedDomains in sandbox.json.` };
		}
		const granted = sessionGranted(k, ctx.cwd);
		if (granted) {
			audit({ layer: 2, tool: k.tool, subject: k.subject, reason: k.reason, decision: "session-grant", grant: granted, cwd: ctx.cwd });
			return null;
		}
	}
	const decision = await askDecision(ctx, k, absoluteDenyPattern);
	if (decision === "no") {
		audit({ layer: 2, tool: k.tool, subject: k.subject, reason: k.reason, decision: "no", cwd: ctx.cwd });
		return { block: true, reason: `${k.tool} blocked: ${k.reason}` };
	}
	if (decision === "session" || decision === "session-folder") {
		const value = decision === "session-folder" ? dirname(k.overrideValue) : k.overrideValue;
		sessionGrants.push({ kind: k.overrideKind, value });
		audit({ layer: 2, tool: k.tool, subject: k.subject, reason: k.reason, decision, grant: value, cwd: ctx.cwd });
		ctx.ui.notify(`security-guard: allowed for this session (not saved) → ${value}`, "info");
		return null;
	}
	if (decision === "always-cwd" || decision === "always-global" || decision === "always-cwd-folder" || decision === "always-global-folder") {
		if (absoluteDenyPattern) {
			audit({ layer: 2, tool: k.tool, subject: k.subject, reason: k.reason, decision: "no", note: "always-refused-for-absolute-deny", cwd: ctx.cwd });
			return { block: true, reason: `${k.tool} blocked: ${k.reason}` };
		}
		const scope: Scope = decision === "always-cwd" || decision === "always-cwd-folder" ? "cwd" : "global";
		const useFolder = decision === "always-cwd-folder" || decision === "always-global-folder";
		const value = useFolder ? dirname(k.overrideValue) : k.overrideValue;
		try {
			const path = persistOverride(scope, ctx.cwd, k.overrideKind, value);
			audit({ layer: 2, tool: k.tool, subject: k.subject, reason: k.reason, decision, scope, granularity: useFolder ? "folder" : "file", cwd: ctx.cwd, persisted_to: path, override: { [k.overrideKind]: value } });
			ctx.ui.notify(`security-guard: persisted ${scope}${useFolder ? " (folder)" : ""} override → ${path}`, "warning");
		} catch (e) {
			audit({ layer: 2, tool: k.tool, subject: k.subject, reason: k.reason, decision: "yes", note: `always-persist-failed: ${e}`, scope, cwd: ctx.cwd });
			ctx.ui.notify(`security-guard: could not persist ${scope} override (${e}); allowing this call only`, "warning");
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
		// A policy file that does not parse is skipped and the defaults apply.
		// Say so loudly: otherwise one trailing comma silently disables the whole file.
		for (const p of [`${getAgentDir()}/extensions/sandbox.json`, `${ctx.cwd}/.pi/sandbox.json`]) {
			const err = policyFileError(p);
			if (!err) continue;
			audit({ layer: 2, event: "policy-parse-error", file: p, error: err, cwd: ctx.cwd });
			console.error(`security-guard: ${p} does not parse (${err}); its rules are NOT applied`);
			ctx.ui.notify(`⚠️  security-guard: ${p} does not parse, so neither layer applies its rules (built-in defaults instead).\n${err}`, "error");
		}
		const policy = loadPolicy(ctx.cwd);
		if (!policy.enabled) {
			active = false;
			ctx.ui.notify("security-guard (Layer 2) disabled: enabled=false in sandbox.json", "info");
			return;
		}
		active = true;
		sessionGrants.length = 0;
		ctx.ui.notify(`🔒 security-guard (Layer 2) active, role: ${policy.layer2 ?? "guard, or floor when pi-permission-system is active"}`, "info");
	});

	pi.on("tool_call", async (event, ctx) => {
		if (!active) return;
		const policy = loadPolicy(ctx.cwd);
		const mode = layer2Mode(policy, ctx as never);

		// --- Path-based gates (with ask-tier prompt) ---
		if (isToolCallEventType("read", event)) {
			const reason = isDeniedRead(event.input.path, ctx.cwd, policy);
			if (reason) {
				const abs = canonicalize(event.input.path, ctx.cwd);
				const result = await askOrBlock(ctx as unknown as UICtx, { layer: 2, tool: "read", subject: abs, reason, overrideKind: "allowRead", overrideValue: abs }, isAbsoluteDeny(abs, ctx.cwd), mode);
				if (result) return result;
			}
		}
		// Read-only search tools. grep returns file contents and runs ripgrep in
		// process, so neither the bash sandbox nor the read gate saw it before.
		// Gate the search root here; tool_result below drops output lines from
		// denied files beneath the root.
		const searchRoot = isToolCallEventType("grep", event) || isToolCallEventType("find", event) || isToolCallEventType("ls", event)
			? (event.input.path ?? ".")
			: null;
		if (searchRoot !== null) {
			const reason = isDeniedRead(searchRoot, ctx.cwd, policy);
			if (reason) {
				const abs = canonicalize(searchRoot, ctx.cwd);
				const result = await askOrBlock(ctx as unknown as UICtx, { layer: 2, tool: event.toolName, subject: abs, reason, overrideKind: "allowRead", overrideValue: abs }, isAbsoluteDeny(abs, ctx.cwd), mode);
				if (result) return result;
			}
		}
		if (isToolCallEventType("write", event)) {
			const reason = isDeniedWrite(event.input.path, ctx.cwd, policy);
			if (reason) {
				const abs = canonicalize(event.input.path, ctx.cwd);
				const result = await askOrBlock(ctx as unknown as UICtx, { layer: 2, tool: "write", subject: abs, reason, overrideKind: "allowWrite", overrideValue: abs }, isAbsoluteDeny(abs, ctx.cwd), mode);
				if (result) return result;
			}
		}
		if (isToolCallEventType("edit", event)) {
			const reason = isDeniedWrite(event.input.path, ctx.cwd, policy);
			if (reason) {
				const abs = canonicalize(event.input.path, ctx.cwd);
				const result = await askOrBlock(ctx as unknown as UICtx, { layer: 2, tool: "edit", subject: abs, reason, overrideKind: "allowWrite", overrideValue: abs }, isAbsoluteDeny(abs, ctx.cwd), mode);
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
				const result = await askOrBlock(ctx as unknown as UICtx, { layer: 2, tool: event.toolName, subject: u, reason, overrideKind: "allowDomains", overrideValue: host }, null, mode);
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

	// grep output filter. A root that passed the gate can still contain denied
	// files (`.env`, `*.pem`, `~/.ssh` under a search of `~`). Approving the
	// root does not approve the denied files beneath it. Runs before the
	// result reaches the model.
	pi.on("tool_result", (event, ctx) => {
		if (!active || event.toolName !== "grep" || event.isError) return;
		const input = event.input as { path?: string } | undefined;
		const policy = loadPolicy(ctx.cwd);
		const root = canonicalize(input?.path ?? ".", ctx.cwd);
		let rootIsDir = false;
		try {
			rootIsDir = statSync(root).isDirectory();
		} catch {
			return;
		}
		// A single-file search prints only the basename; its root gate already decided.
		if (!rootIsDir) return;
		let removedLines = 0;
		const removedFiles = new Set<string>();
		const content = event.content.map((c) => {
			if (c.type !== "text") return c;
			const r = filterGrepOutput(c.text, (printed) => isDeniedRead(join(root, printed), ctx.cwd, policy) !== null);
			removedLines += r.removedLines;
			for (const f of r.removedFiles) removedFiles.add(f);
			return { ...c, text: r.text };
		});
		if (removedLines === 0) return;
		audit({ layer: 2, tool: "grep", subject: root, decision: "redacted", removedLines, removedFiles: [...removedFiles], cwd: ctx.cwd });
		content.push({ type: "text", text: `\n[security-guard: removed ${removedLines} line(s) from ${removedFiles.size} file(s) that match the read-deny policy]` });
		return { content };
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
				`  layer2:            ${layer2Mode(policy, ctx as never)}${policy.layer2 ? "" : " (auto-detected)"}`,
				`  session grants:    ${sessionGrants.map((g) => `${g.kind}:${g.value}`).join(", ") || "(none)"}`,
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
