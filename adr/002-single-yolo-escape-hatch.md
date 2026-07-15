# ADR-002: Single --yolo escape hatch, not per-layer toggles

**Status:** Accepted

## Context

Every security layer adds friction. Users need a way to escape when debugging or when the policy is too tight. The question is whether that escape is per-layer or global.

## Decision

One global `--yolo` / `--no-sandbox` flag disables all layers simultaneously and prints a visible warning banner. There are no per-layer toggles exposed as flags.

Disabling a single layer in isolation (e.g. Layer 2 only) is still possible by setting `"enabled": false` in `sandbox.json`, but that is a deliberate config change, not a runtime flag.

## Consequences

- Users cannot accidentally leave one layer disabled while another is active.
- The warning banner on `--yolo` makes the unsandboxed state visible and auditable in the terminal.
- **Rejected alternative:** per-tool `--allow-X` flags (Claude Code style). Too much surface area for a single-developer tool; revisit if corporate multi-user use cases emerge.
