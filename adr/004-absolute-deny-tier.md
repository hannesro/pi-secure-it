# ADR-004: Absolute-deny tier for credential material

**Status:** Accepted

## Context

The ask-tier prompts (ADR-003) let users grant access with a single selection. For credential material (`~/.ssh`, `~/.gnupg`, `~/.aws`, `*.pem`, `*.key`) that level of friction is insufficient — a prompt-injected or confused model could trick a user into clicking "yes" quickly.

## Decision

Paths matching the absolute-deny patterns are in a separate tier:

- The normal selection prompt is replaced by a free-text input that requires typing `"i understand"` verbatim.
- The "always" persistence options are never offered for these paths — even if the user types the confirmation, the allow is for that single call only.
- The patterns are hardcoded in the extension, not configurable from `sandbox.json`.

Hardcoded patterns: `~/.ssh`, `~/.gnupg`, `~/.aws`, `*.pem`, `*.key`.

## Consequences

- Accidental or prompt-injected access to credential material is significantly harder.
- Users with legitimate reasons (e.g. a key-management tool) must use `--yolo` for the session, which is intentionally inconvenient and visible.
- The hardcoded list is intentionally small; adding to it requires a code change and a deliberate decision.
