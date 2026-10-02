/**
 * Pure helpers shared by security-guard.ts (Layer 2) and sandbox/index.ts
 * (Layer 1). No pi imports, so security/tests/*.mjs can import this file
 * directly (Node 24 strips the types) instead of re-implementing it.
 */

import { existsSync, readFileSync } from "node:fs";

/**
 * Check that a policy file, if present, parses as JSON. Returns the parse
 * error message, or null when the file is absent or valid.
 *
 * Both layers fall back to their built-in defaults when a file does not
 * parse. That fallback is silent from the user's point of view unless the
 * caller surfaces this result: a single trailing comma otherwise disables a
 * whole policy file without anyone noticing.
 */
export function policyFileError(path: string): string | null {
	if (!existsSync(path)) return null;
	try {
		JSON.parse(readFileSync(path, "utf-8"));
		return null;
	} catch (e) {
		return e instanceof Error ? e.message : String(e);
	}
}

/**
 * Read a policy file for an in-place update ("always" prompt tiers).
 * Absent file: empty object. Unparseable file: throws, so the caller never
 * overwrites a hand-written policy it could not read.
 */
export function readPolicyForUpdate(path: string): Record<string, unknown> {
	if (!existsSync(path)) return {};
	try {
		return JSON.parse(readFileSync(path, "utf-8"));
	} catch (e) {
		throw new Error(`refusing to overwrite ${path}: it does not parse as JSON (${e instanceof Error ? e.message : e})`);
	}
}

/**
 * One line of pi's grep tool output: `path:N: text` for a match,
 * `path-N- text` for a context line. The separator is the same on both sides
 * of the line number, which keeps paths containing `-` or `:` parseable.
 */
const GREP_LINE = /^(.+?)([:-])(\d+)\2 /;

export interface GrepFilterResult {
	text: string;
	removedLines: number;
	removedFiles: string[];
}

/**
 * Remove grep output lines that come from denied files.
 *
 * `isDenied` receives the path exactly as grep printed it (relative to the
 * search root for a directory search). Lines that are not match or context
 * lines (`--` separators, truncation notices) are kept. Decisions are cached
 * per path.
 */
export function filterGrepOutput(text: string, isDenied: (printedPath: string) => boolean): GrepFilterResult {
	const cache = new Map<string, boolean>();
	const removedFiles = new Set<string>();
	let removedLines = 0;
	const kept: string[] = [];
	for (const line of text.split("\n")) {
		const m = GREP_LINE.exec(line);
		if (m) {
			const file = m[1];
			let denied = cache.get(file);
			if (denied === undefined) {
				denied = isDenied(file);
				cache.set(file, denied);
			}
			if (denied) {
				removedLines++;
				removedFiles.add(file);
				continue;
			}
		}
		kept.push(line);
	}
	return { text: kept.join("\n"), removedLines, removedFiles: [...removedFiles] };
}

// ---------- Layer 2 role (ADR-011) ----------

export type Layer2Mode = "guard" | "floor";

/** Where @gotgenes/pi-permission-system publishes one service per session (its cross-extension API). */
export const PERMISSION_SYSTEM_SERVICES = Symbol.for("@gotgenes/pi-permission-system:session-services");

type SessionLike = { sessionManager?: { getSessionId?: () => string } };

/** Whether pi-permission-system published a service for this session. */
export function permissionSystemActive(ctx: SessionLike, store: Record<symbol, unknown> = globalThis as Record<symbol, unknown>): boolean {
	const services = store[PERMISSION_SYSTEM_SERVICES];
	const id = ctx.sessionManager?.getSessionId?.();
	return services instanceof Map && typeof id === "string" && services.has(id);
}

/** The configured role, or "floor" when pi-permission-system is active for the session, else "guard". */
export function layer2Mode(policy: { layer2?: Layer2Mode }, ctx: SessionLike, store?: Record<symbol, unknown>): Layer2Mode {
	return policy.layer2 ?? (permissionSystemActive(ctx, store) ? "floor" : "guard");
}

// ---------- Layer 1 violation attribution ----------

const EPERM_RE = /operation not permitted|EPERM|EACCES/i;

/**
 * The path a sandboxed bash command was refused, from its error output, as
 * an absolute path. Handles `tool: ./rel: Operation not permitted`,
 * quoted paths (`cannot touch 'x.pem'`), `~/…` and absolute paths. Relative
 * paths resolve against the command's working directory, never against `/`.
 */
export function extractBlockedPath(output: string, cwd: string, home: string): string | undefined {
	for (const line of output.split("\n").reverse()) {
		const m = EPERM_RE.exec(line);
		if (!m) continue;
		// The segment right before the error text, e.g. "grep: ./.env: Operation…" → "./.env".
		const before = line.slice(0, m.index).replace(/[\s:]+$/, "");
		const segment = before.split(/:\s+/).pop() ?? "";
		const quoted = /['"“‘`]([^'"”’`]+)['"”’`]\s*$/.exec(segment);
		let token = (quoted?.[1] ?? segment.split(/\s+/).pop() ?? "").trim();
		if (!token || /^(bash|sh|zsh)$/.test(token)) continue;
		if (token === "~" || token.startsWith("~/")) token = home + token.slice(1);
		const abs = token.startsWith("/") ? token : `${cwd.replace(/\/+$/, "")}/${token}`;
		return normalizeAbs(abs);
	}
	return undefined;
}

function normalizeAbs(p: string): string {
	const out: string[] = [];
	for (const part of p.split("/")) {
		if (!part || part === ".") continue;
		if (part === "..") out.pop();
		else out.push(part);
	}
	return `/${out.join("/")}`;
}

/** A folder Layer 1 may offer as a one-click write grant: never `/`, the home folder, or anything above it. */
export function isSafeFolderGrant(dir: string, home: string): boolean {
	const d = normalizeAbs(dir);
	const h = normalizeAbs(home);
	return d !== "/" && d !== h && !h.startsWith(`${d}/`);
}

/**
 * Whether an absolute path matches one of the policy's path patterns, with the
 * same semantics as Layer 2: `/…` and `~/…` are full-path prefixes or globs,
 * `.` is the project root, anything else matches the basename (glob allowed).
 */
export function matchesPolicyPattern(absPath: string, pattern: string, cwd: string, home: string): boolean {
	const p = pattern === "~" ? home : pattern.startsWith("~/") ? `${home}/${pattern.slice(2)}` : pattern;
	const ci = process.platform === "darwin" ? "i" : "";
	const glob = (s: string) =>
		new RegExp(`^${s.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*\*/g, "\x00").replace(/\*/g, "[^/]*").replace(/\x00/g, ".*").replace(/\?/g, "[^/]")}$`, ci);
	if (p === ".") return absPath === cwd || absPath.startsWith(`${cwd}/`);
	if (p.startsWith("/")) return p.includes("*") ? glob(p).test(absPath) : absPath === p || absPath.startsWith(`${p}/`);
	const base = absPath.slice(absPath.lastIndexOf("/") + 1);
	return p.includes("*") ? glob(p).test(base) : ci ? base.toLowerCase() === p.toLowerCase() : base === p;
}
