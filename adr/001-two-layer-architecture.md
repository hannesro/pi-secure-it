# ADR-001: Two-layer security architecture

**Status:** Accepted

## Context

Pi's built-in `bash` tool spawns child processes. An OS-level sandbox can restrict those processes, but the in-process Node tools (`read`, `write`, `edit`, `fetch_content`, `web_search`, `get_search_content`) run inside pi's own process and bypass any OS sandbox entirely.

## Decision

Two complementary layers, each covering the blind spot of the other:

- **Layer 1** — OS-level sandbox (`sandbox-exec` on macOS, `bubblewrap` on Linux) wrapping the `bash` tool. Blocks at the OS level before any code runs.
- **Layer 2** — In-process `tool_call` hook applied to the Node tools that Layer 1 cannot reach.

Both layers read the same `sandbox.json` policy so they cannot drift apart.

## Consequences

- A write blocked by Layer 2 is not retried through `bash`; the model sees a clean block reason.
- Adding a new allow-list entry in one place (`sandbox.json`) is immediately respected by both layers.
- Layer 1 requires `sandbox-exec` (macOS built-in) or `bubblewrap` + `socat` (Linux). Windows is unsupported.
