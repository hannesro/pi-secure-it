# ADR-006: Path canonicalization walks up to the deepest existing ancestor

**Status:** Accepted

## Context

Symlinks can be used to escape a sandbox. A path like `<cwd>/link-to-ssh/id_rsa` resolves to `~/.ssh/id_rsa` if `link-to-ssh` is a symlink to `~/.ssh`. `realpathSync` only works on paths that exist. If the leaf (`id_rsa`) doesn't exist yet (e.g. a write attempt) the naive approach fails to follow the symlink at all.

## Decision

`canonicalize(path, cwd)` walks up the path one component at a time until it finds an ancestor that exists, calls `realpathSync` on that ancestor, then re-appends the remaining non-existent components. This resolves all existing symlinks in the path prefix even when the leaf does not exist yet.

```
canonicalize("cwd/link-to-ssh/new-file", cwd)
  → "cwd/link-to-ssh" exists → realpathSync → "/Users/you/.ssh"
  → result: "/Users/you/.ssh/new-file"   ← correctly matched by ~/.ssh pattern
```

## Consequences

- Symlink-escape attacks are blocked even for write paths that don't exist yet.
- The canonicalized path (not the raw input) is what gets matched against policy and shown to the user in the prompt.
- Accepted limitation: if the entire path is under a non-existent root (no existing ancestor at all), canonicalization falls back to the raw absolute path. This is an extreme edge case with no practical attack vector.
