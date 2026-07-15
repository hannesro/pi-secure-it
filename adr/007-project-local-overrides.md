# ADR-007: Project-local overrides live in an additive `overrides` section

**Status:** Accepted

## Context

The ask-tier "always for CURRENT project" option needs to persist an allow-list entry somewhere the user can inspect and revoke it, without stomping on the rest of their policy.

Two options were considered:
1. Append directly to `filesystem.allowWrite` / `network.allowedDomains` in `<cwd>/.pi/sandbox.json`.
2. Write to a dedicated `overrides` section that is merged additively on top of the global policy.

## Decision

Write to an `overrides` section (`overrides.allowRead`, `overrides.allowWrite`, `overrides.allowDomains`). The policy loader merges `overrides` additively — it never replaces or truncates the base policy arrays.

```json
// <cwd>/.pi/sandbox.json  — written by ask-tier prompts
{
  "overrides": {
    "allowWrite": ["/Users/you/apps/obsidian/vaults/work/Notes/"]
  }
}
```

## Consequences

- The user can see exactly what was auto-granted at a glance — it's all in `overrides`, not mixed into the base policy.
- Revoking a project grant is a single array-entry deletion with no risk of accidentally editing the global allow-list.
- The global `sandbox.json` is never written by prompts — only deliberate manual edits change global policy.
- `<cwd>/.pi/sandbox.json` is gitignored by default so project overrides don't leak into team repos.
