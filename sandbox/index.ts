/**
 * Sandbox Extension - OS-level sandboxing for bash commands
 *
 * Uses @anthropic-ai/sandbox-runtime to enforce filesystem and network
 * restrictions on bash commands at the OS level (sandbox-exec on macOS,
 * bubblewrap on Linux).
 *
 * Note: this example intentionally overrides the built-in `bash` tool to show
 * how built-in tools can be replaced. Alternatively, you could sandbox `bash`
 * via `tool_call` input mutation without replacing the tool.
 *
 * Config files (merged, project takes precedence):
 * - ~/.pi/agent/extensions/sandbox.json (global)
 * - <cwd>/.pi/sandbox.json (project-local)
 *
 * Example .pi/sandbox.json:
 * ```json
 * {
 *   "enabled": true,
 *   "network": {
 *     "allowedDomains": ["github.com", "*.github.com"],
 *     "deniedDomains": []
 *   },
 *   "filesystem": {
 *     "denyRead": ["~/.ssh", "~/.aws"],
 *     "allowWrite": [".", "/tmp"],
 *     "denyWrite": [".env"]
 *   }
 * }
 * ```
 *
 * Usage:
 * - `pi` - sandbox enabled with default/config settings (secure by default)
 * - `pi --yolo` - disable all security layers (visible warning banner)
 * - `pi --no-sandbox` - alias for --yolo (hidden, for backwards compat)
 * - `/sandbox` - show current sandbox configuration
 *
 * Setup:
 * 1. Copy sandbox/ directory to ~/.pi/agent/extensions/
 * 2. Run `npm install` in ~/.pi/agent/extensions/sandbox/
 *
 * Linux also requires: bubblewrap, socat, ripgrep
 */

import { spawn } from "node:child_process";
import { existsSync, readFileSync, mkdirSync, writeFileSync, appendFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { SandboxManager, type SandboxRuntimeConfig } from "@anthropic-ai/sandbox-runtime";
import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { type BashOperations, createBashTool, getAgentDir } from "@mariozechner/pi-coding-agent";

interface SandboxConfig extends SandboxRuntimeConfig {
	enabled?: boolean;
	/**
	 * Additive project-local overrides written by the Layer 1 ask-tier
	 * prompt (and shared with Layer 2 via the same <cwd>/.pi/sandbox.json).
	 * Read by loadConfig() and folded into filesystem.allowWrite /
	 * network.allowedDomains so the OS-level sandbox honors them.
	 */
	overrides?: {
		allowRead?: string[];
		allowWrite?: string[];
		allowDomains?: string[];
	};
}

const DEFAULT_CONFIG: SandboxConfig = {
	enabled: true,
	network: {
		allowedDomains: [
			"npmjs.org",
			"*.npmjs.org",
			"registry.npmjs.org",
			"registry.yarnpkg.com",
			"pypi.org",
			"*.pypi.org",
			"github.com",
			"*.github.com",
			"api.github.com",
			"raw.githubusercontent.com",
		],
		deniedDomains: [],
	},
	filesystem: {
		denyRead: ["~/.ssh", "~/.aws", "~/.gnupg"],
		allowWrite: [".", "/tmp"],
		denyWrite: [".env", ".env.*", "*.pem", "*.key"],
	},
};

function loadConfig(cwd: string): SandboxConfig {
	const projectConfigPath = join(cwd, ".pi", "sandbox.json");
	const globalConfigPath = join(getAgentDir(), "extensions", "sandbox.json");

	let globalConfig: Partial<SandboxConfig> = {};
	let projectConfig: Partial<SandboxConfig> = {};

	if (existsSync(globalConfigPath)) {
		try {
			globalConfig = JSON.parse(readFileSync(globalConfigPath, "utf-8"));
		} catch (e) {
			console.error(`Warning: Could not parse ${globalConfigPath}: ${e}`);
		}
	}

	if (existsSync(projectConfigPath)) {
		try {
			projectConfig = JSON.parse(readFileSync(projectConfigPath, "utf-8"));
		} catch (e) {
			console.error(`Warning: Could not parse ${projectConfigPath}: ${e}`);
		}
	}

	return foldOverrides(deepMerge(deepMerge(DEFAULT_CONFIG, globalConfig), projectConfig));
}

/**
 * Fold an additive `overrides` section into the regular allowWrite /
 * allowedDomains arrays so SandboxManager (which doesn't know about
 * `overrides`) sees a flat config. Idempotent.
 */
function foldOverrides(config: SandboxConfig): SandboxConfig {
	const overrides = config.overrides;
	if (!overrides) return config;
	const out: SandboxConfig = {
		...config,
		filesystem: config.filesystem
			? { ...config.filesystem }
			: { denyRead: [], allowWrite: [], denyWrite: [] },
		network: config.network ? { ...config.network } : { allowedDomains: [], deniedDomains: [] },
	};
	if (overrides.allowWrite?.length) {
		out.filesystem!.allowWrite = [
			...(out.filesystem!.allowWrite ?? []),
			...overrides.allowWrite,
		];
	}
	if (overrides.allowDomains?.length) {
		out.network!.allowedDomains = [
			...(out.network!.allowedDomains ?? []),
			...overrides.allowDomains,
		];
	}
	// allowRead intentionally NOT folded into denyRead removal: Layer 1
	// treats sensitive paths as hard-deny. Layer 2 honors allowRead at
	// prompt-time as a model-tool gate. Keeping them split prevents an
	// "always" decision in Layer 2 from accidentally widening the OS
	// sandbox.
	return out;
}

function deepMerge(base: SandboxConfig, overrides: Partial<SandboxConfig>): SandboxConfig {
	const result: SandboxConfig = { ...base };

	if (overrides.enabled !== undefined) result.enabled = overrides.enabled;
	if (overrides.network) {
		result.network = { ...base.network, ...overrides.network };
	}
	if (overrides.filesystem) {
		result.filesystem = { ...base.filesystem, ...overrides.filesystem };
	}
	if (overrides.overrides) {
		result.overrides = {
			allowRead: [...(base.overrides?.allowRead ?? []), ...(overrides.overrides.allowRead ?? [])],
			allowWrite: [...(base.overrides?.allowWrite ?? []), ...(overrides.overrides.allowWrite ?? [])],
			allowDomains: [...(base.overrides?.allowDomains ?? []), ...(overrides.overrides.allowDomains ?? [])],
		};
	}

	const extOverrides = overrides as {
		ignoreViolations?: Record<string, string[]>;
		enableWeakerNestedSandbox?: boolean;
	};
	const extResult = result as { ignoreViolations?: Record<string, string[]>; enableWeakerNestedSandbox?: boolean };

	if (extOverrides.ignoreViolations) {
		extResult.ignoreViolations = extOverrides.ignoreViolations;
	}
	if (extOverrides.enableWeakerNestedSandbox !== undefined) {
		extResult.enableWeakerNestedSandbox = extOverrides.enableWeakerNestedSandbox;
	}

	return result;
}

function createSandboxedBashOps(opts?: {
	ctx?: { cwd: string; hasUI?: boolean; ui?: { select?: (t: string, o: string[], op?: { timeout?: number }) => Promise<string | undefined>; notify?: (m: string, l?: string) => void } };
	onAlways?: (absPath: string, scope: "cwd" | "global") => Promise<string>;
}): BashOperations {
	return {
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
					env: { ...process.env, TMPDIR: `${piTmp}/` },
				});

				let timedOut = false;
				let timeoutHandle: NodeJS.Timeout | undefined;

				if (timeout !== undefined && timeout > 0) {
					timeoutHandle = setTimeout(() => {
						timedOut = true;
						if (child.pid) {
							try {
								process.kill(-child.pid, "SIGKILL");
							} catch {
								child.kill("SIGKILL");
							}
						}
					}, timeout * 1000);
				}

				let outputTail = "";
				const captureOut = (chunk: Buffer | string) => {
					outputTail = (outputTail + chunk.toString()).slice(-2048);
					onData(chunk);
				};
				child.stdout?.on("data", captureOut);
				child.stderr?.on("data", captureOut);

				child.on("error", (err) => {
					if (timeoutHandle) clearTimeout(timeoutHandle);
					reject(err);
				});

				const onAbort = () => {
					if (child.pid) {
						try {
							process.kill(-child.pid, "SIGKILL");
						} catch {
							child.kill("SIGKILL");
						}
					}
				};

				signal?.addEventListener("abort", onAbort, { once: true });

				child.on("close", async (code) => {
					if (timeoutHandle) clearTimeout(timeoutHandle);
					signal?.removeEventListener("abort", onAbort);

					let offending: string | undefined;
					if (/operation not permitted|EPERM|EACCES/i.test(outputTail)) {
						const pathMatch = outputTail.match(/['“‘]?(\/[\w./~+-]+|~\/[\w./+-]+)['”’]?\s*:?\s*(?:operation not permitted|EPERM|EACCES)/i);
						offending = pathMatch?.[1];
						const configDirHint = offending && /\.config\/|\.kube\/|\.docker\/|\.netrc|\.aws\/|\.npmrc|\.gitconfig/.test(offending);

						let hint = `\n💡 pi-sandbox: filesystem access blocked.\n`;
						if (offending) hint += `   Path: ${offending}\n`;
						hint += `   This is the pi sandbox (Layer 1), NOT macOS Full Disk Access / TCC.\n`;
						if (configDirHint) {
							hint +=
								`   Looks like a tool's own config dir. To allow this tool in the\n` +
								`   current project, add a project-local policy:\n` +
								`     mkdir -p ${cwd}/.pi && cat > ${cwd}/.pi/sandbox.json <<'JSON'\n` +
								`     { "filesystem": { "allowWrite": [".", "${offending?.replace(/^~/, "$HOME") ?? "~/.config/<tool>"}"] } }\n` +
								`     JSON\n` +
								`   Or run pi with --yolo for one-off elevated access (disables ALL layers).\n`;
						} else {
							hint +=
								`   Use $TMPDIR (= ${piTmp}/) for scratch files,\n` +
								`   or write inside the project directory (${cwd}).\n`;
						}
						hint += `   Policy: ~/.pi/agent/extensions/sandbox.json (+ <cwd>/.pi/sandbox.json overrides).\n`;
						if (opts?.ctx?.hasUI && opts.ctx.ui?.select && opts.onAlways) {
							hint += `   → Waiting for your decision in the prompt above before this bash call returns to the model.\n`;
						}
						onData(Buffer.from(hint));
					}

					// Ask-tier prompt: BEFORE resolve so the agent loop pauses while the
					// user decides. Otherwise the model gets the EPERM hint immediately,
					// tries an alternative, and the prompt sits orphaned in the UI.
					let decisionHint = "";
					if (offending && opts?.ctx?.hasUI && opts.ctx.ui?.select && opts.onAlways) {
						const absPath = offending.startsWith("~") ? offending.replace(/^~/, process.env.HOME ?? "~") : offending;
						const title = `Layer 1 (bash sandbox) blocked write to:\n  ${absPath}\n\nAllow future bash commands to write here?`;
						const parentDir = dirname(absPath);
						const options = [
							"always for CURRENT project — whitelist this file (.pi/sandbox.json)",
							`always for CURRENT project — whitelist parent folder ${parentDir} (.pi/sandbox.json)`,
							"always for ALL projects — whitelist this file (~/.pi/agent/extensions/sandbox.json)",
							`always for ALL projects — whitelist parent folder ${parentDir} (~/.pi/agent/extensions/sandbox.json)`,
							"no  — leave blocked (default)",
						];
						try {
							const chosen = await opts.ctx.ui.select(title, options, { timeout: 60_000 });
							const ts = new Date().toISOString();
							const auditPath = `${getAgentDir()}/audit.log`;
							const scope: "cwd" | "global" | null =
								chosen === options[0] || chosen === options[1] ? "cwd"
								: chosen === options[2] || chosen === options[3] ? "global"
								: null;
							const useParent = chosen === options[1] || chosen === options[3];
							const subject = useParent ? parentDir : absPath;
							if (scope) {
								try {
									const persistedTo = await opts.onAlways(subject, scope);
									appendFileSync(auditPath, `${JSON.stringify({ ts, layer: 1, tool: "bash", subject, granularity: useParent ? "folder" : "file", original: absPath, decision: scope === "cwd" ? "always-cwd" : "always-global", scope, cwd: opts.ctx.cwd, persisted_to: persistedTo })}\n`);
									opts.ctx.ui?.notify?.(`pi-sandbox: allowed ${subject} (${scope}${useParent ? ", folder" : ""}) — retry the bash command`, "warning");
									decisionHint = `\n✅ pi-sandbox: ${subject} now allowed (${scope}${useParent ? ", folder" : ""}). Retry the bash command.\n`;
								} catch (e) {
									appendFileSync(auditPath, `${JSON.stringify({ ts, layer: 1, tool: "bash", subject, granularity: useParent ? "folder" : "file", original: absPath, decision: scope === "cwd" ? "always-cwd" : "always-global", scope, cwd: opts.ctx.cwd, error: String(e) })}\n`);
									opts.ctx.ui?.notify?.(`pi-sandbox: failed to apply override (${e})`, "error");
									decisionHint = `\n❌ pi-sandbox: failed to apply override (${e}). Path remains blocked.\n`;
								}
							} else {
								appendFileSync(auditPath, `${JSON.stringify({ ts, layer: 1, tool: "bash", subject: absPath, decision: "no", cwd: opts.ctx.cwd })}\n`);
								decisionHint = `\n❌ pi-sandbox: user denied. ${absPath} remains blocked. Do not retry; ask the user how to proceed.\n`;
							}
						} catch {
							/* prompt failure shouldn't crash bash */
						}
						if (decisionHint) onData(Buffer.from(decisionHint));
					}

					if (signal?.aborted) {
						reject(new Error("aborted"));
					} else if (timedOut) {
						reject(new Error(`timeout:${timeout}`));
					} else {
						resolve({ exitCode: code });
					}
				});
			});
		},
	};
}

export default function (pi: ExtensionAPI) {
	pi.registerFlag("yolo", {
		description: "Disable all pi security layers (no-sandbox, no in-process guard, no browser gate). Use with caution.",
		type: "boolean",
		default: false,
	});

	// Backwards compat alias
	pi.registerFlag("no-sandbox", {
		description: "(Deprecated) alias for --yolo. Use --yolo instead.",
		type: "boolean",
		default: false,
	});

	const localCwd = process.cwd();
	const localBash = createBashTool(localCwd);

	let sandboxEnabled = false;
	let sandboxInitialized = false;
	let activeCtx: { cwd: string; hasUI?: boolean; ui?: { select?: (t: string, o: string[], op?: { timeout?: number }) => Promise<string | undefined>; notify?: (m: string, l?: string) => void } } | undefined;

	/** Persist an "always" Layer 1 override (scope: cwd or global) and live-reload SandboxManager. */
	async function persistAndReload(absPath: string, scope: "cwd" | "global"): Promise<string> {
		const { dir, path } =
			scope === "cwd"
				? { dir: join(localCwd, ".pi"), path: join(localCwd, ".pi", "sandbox.json") }
				: { dir: join(getAgentDir(), "extensions"), path: join(getAgentDir(), "extensions", "sandbox.json") };
		let existing: Record<string, unknown> & { overrides?: { allowWrite?: string[] } } = {};
		if (existsSync(path)) {
			try {
				existing = JSON.parse(readFileSync(path, "utf-8"));
			} catch {
				/* overwrite corrupt */
			}
		}
		const overrides = (existing.overrides ?? {}) as { allowWrite?: string[] };
		const list = overrides.allowWrite ?? [];
		if (!list.includes(absPath)) list.push(absPath);
		overrides.allowWrite = list;
		existing.overrides = overrides;
		mkdirSync(dir, { recursive: true });
		writeFileSync(path, `${JSON.stringify(existing, null, 2)}\n`);
		await reloadSandbox();
		return path;
	}

	async function reloadSandbox(): Promise<void> {
		if (!sandboxInitialized) return;
		const config = loadConfig(localCwd);
		const configExt = config as unknown as { ignoreViolations?: Record<string, string[]>; enableWeakerNestedSandbox?: boolean };
		try {
			await SandboxManager.reset();
		} catch {
			/* ignore */
		}
		await SandboxManager.initialize({
			network: config.network,
			filesystem: config.filesystem
				? {
						denyRead: config.filesystem.denyRead,
						allowWrite: config.filesystem.allowWrite,
						denyWrite: config.filesystem.denyWrite,
					}
				: undefined,
			ignoreViolations: configExt.ignoreViolations,
			enableWeakerNestedSandbox: configExt.enableWeakerNestedSandbox,
		});
	}

	pi.registerTool({
		...localBash,
		label: "bash (sandboxed)",
		async execute(id, params, signal, onUpdate, _ctx) {
			if (!sandboxEnabled || !sandboxInitialized) {
				return localBash.execute(id, params, signal, onUpdate);
			}

			const sandboxedBash = createBashTool(localCwd, {
				operations: createSandboxedBashOps({ ctx: activeCtx, onAlways: persistAndReload }),
			});
			return sandboxedBash.execute(id, params, signal, onUpdate);
		},
	});

	pi.on("user_bash", () => {
		if (!sandboxEnabled || !sandboxInitialized) return;
		return { operations: createSandboxedBashOps({ ctx: activeCtx, onAlways: persistAndReload }) };
	});

	pi.on("session_start", async (_event, ctx) => {
		activeCtx = ctx as unknown as typeof activeCtx;
		const yolo = pi.getFlag("yolo") as boolean;
		const noSandbox = pi.getFlag("no-sandbox") as boolean; // backwards compat

		if (yolo || noSandbox) {
			sandboxEnabled = false;
			ctx.ui.setStatus(
				"sandbox",
				ctx.ui.theme.fg("error", "⚠️  YOLO — security layers disabled"),
			);
			ctx.ui.notify(
				"⚠️  YOLO mode — all pi security layers disabled for this session.\n" +
				"   Layer 1 (bash sandbox): OFF\n" +
				"   Layer 2 (in-process guard): OFF\n" +
				"   Layer 3 (subagent stricter): OFF\n" +
				"   Layer 4 (browser gate): OFF\n" +
				"   You can now do anything, including reading secrets and writing system paths.",
				"error",
			);
			return;
		}

		const config = loadConfig(ctx.cwd);

		if (!config.enabled) {
			sandboxEnabled = false;
			ctx.ui.notify("Sandbox disabled via config", "info");
			return;
		}

		const platform = process.platform;
		if (platform !== "darwin" && platform !== "linux") {
			sandboxEnabled = false;
			ctx.ui.notify(`Sandbox not supported on ${platform}`, "warning");
			return;
		}

		try {
			const configExt = config as unknown as {
				ignoreViolations?: Record<string, string[]>;
				enableWeakerNestedSandbox?: boolean;
			};

			await SandboxManager.initialize({
				network: config.network,
				// Strip pi-only fields (modelDenyRead, _comment_*) so SandboxManager
				// doesn't see keys it doesn't understand. modelDenyRead is
				// enforced by Layer 2 (security-guard.ts), not sandbox-exec.
				filesystem: config.filesystem
					? {
							denyRead: config.filesystem.denyRead,
							allowWrite: config.filesystem.allowWrite,
							denyWrite: config.filesystem.denyWrite,
						}
					: undefined,
				ignoreViolations: configExt.ignoreViolations,
				enableWeakerNestedSandbox: configExt.enableWeakerNestedSandbox,
			});

			sandboxEnabled = true;
			sandboxInitialized = true;

			const networkCount = config.network?.allowedDomains?.length ?? 0;
			const writeCount = config.filesystem?.allowWrite?.length ?? 0;
			ctx.ui.setStatus(
				"sandbox",
				ctx.ui.theme.fg("accent", `🔒 Sandbox: ${networkCount} domains, ${writeCount} write paths`),
			);
			ctx.ui.notify("Sandbox initialized", "info");
		} catch (err) {
			sandboxEnabled = false;
			ctx.ui.notify(`Sandbox initialization failed: ${err instanceof Error ? err.message : err}`, "error");
		}
	});

	pi.on("session_shutdown", async () => {
		if (sandboxInitialized) {
			try {
				await SandboxManager.reset();
			} catch {
				// Ignore cleanup errors
			}
		}
	});

	pi.registerCommand("sandbox", {
		description: "Show sandbox configuration. `/sandbox reload` to reload after manual edits to sandbox.json.",
		handler: async (args, ctx) => {
			const sub = (args ?? "").trim().toLowerCase();
			if (sub === "reload") {
				if (!sandboxEnabled || !sandboxInitialized) {
					ctx.ui.notify("Sandbox is disabled — nothing to reload", "info");
					return;
				}
				try {
					await reloadSandbox();
					ctx.ui.notify("🔄 Sandbox reloaded from disk (global + project sandbox.json)", "info");
				} catch (e) {
					ctx.ui.notify(`Sandbox reload failed: ${e instanceof Error ? e.message : e}`, "error");
				}
				return;
			}
			if (!sandboxEnabled) {
				ctx.ui.notify("Sandbox is disabled", "info");
				return;
			}

			const config = loadConfig(ctx.cwd);
			const lines = [
				"Sandbox Configuration:",
				"",
				"Network:",
				`  Allowed: ${config.network?.allowedDomains?.join(", ") || "(none)"}`,
				`  Denied: ${config.network?.deniedDomains?.join(", ") || "(none)"}`,
				"",
				"Filesystem:",
				`  Deny Read: ${config.filesystem?.denyRead?.join(", ") || "(none)"}`,
				`  Allow Write: ${config.filesystem?.allowWrite?.join(", ") || "(none)"}`,
				`  Deny Write: ${config.filesystem?.denyWrite?.join(", ") || "(none)"}`,
			];
			ctx.ui.notify(lines.join("\n"), "info");
		},
	});
}
