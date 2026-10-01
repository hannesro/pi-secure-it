# ADR-010: Ask-tier prompt pre-selects "no" and offers session grants

**Status:** Accepted

## Context

The ask-tier prompt (ADR-003) listed `yes — this once` first, and pi pre-selects the first option, so Enter alone approved. That is the reflexive approval ADR-004 and ADR-009 close for credential material. Repeated prompts for the same file or domain in one session made the reflex worse, and the only alternatives were "this once" or a persistent "always" written to `sandbox.json`.

## Decision

- `no — block` is the first and pre-selected option. Enter, Escape or a timeout blocks.
- New `yes — for this session` options: this file, its parent folder, or this domain. The grant lives in memory, is cleared at `session_start`, and is never written to `sandbox.json`. Later calls it covers run without a prompt and are audited as `session-grant`.
- Session grants never apply to the absolute-deny tier.

## Consequences

- Approving takes one deliberate arrow key; repeated prompts in one session go away without persisting anything.
- `/security` lists the current session grants.
