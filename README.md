# pi-secure-it

Two-layer security extension for the [Pi coding agent](https://pi.dev):

- **Layer 1** — OS-level bash sandbox (`sandbox-exec` on macOS, `bubblewrap` on Linux) that blocks filesystem writes outside an allow-list, reads of sensitive paths, and network egress to unlisted domains.
- **Layer 2** — In-process tool guard applying the same policy to the tools the OS sandbox can't reach: `read`, `write`, `edit`, `fetch_content`, `web_search`, `get_search_content`.
- **Layer 3** — Subagent posture: optionally drop or restrict network access when running headless (`-p`, JSON mode, subagents).

When a tool call is blocked you get an interactive prompt — no need to leave pi and hand-edit config files. Choose *this once*, *always for this project*, or *always for all projects* (file or parent-folder granularity). Decisions are persisted and audited.

## Install

```bash
# From npm (once published)
pi install npm:pi-secure-it

# From git
pi install git:github.com/hannesro/pi-secure-it

# Try without installing
pi -e git:github.com/hannesro/pi-secure-it
```

## Requirements

- macOS or Linux
- macOS: `sandbox-exec` is built in
- Linux: `bubblewrap`, `socat`

## Configuration

Policy files are merged in order:

| File | Scope |
|------|-------|
| `~/.pi/agent/extensions/sandbox.json` | Global (all projects) |
| `<cwd>/.pi/sandbox.json` | Project-local (auto-written by ask-tier prompts) |

Copy `sandbox.example.json` from this package as a starting point for your global config.

### Key fields

```jsonc
{
  "enabled": true,                      // set false to disable Layer 2 without --yolo
  "network": {
    "allowedDomains": [                 // domains fetch_content / get_search_content may reach
      "github.com", "*.github.com",
      "registry.npmjs.org"
    ],
    "deniedDomains": []                 // explicit block-list (checked before allowedDomains)
  },
  "filesystem": {
    "denyRead": ["~/.ssh", "~/.aws"],   // Layer 1 + Layer 2: no read at all
    "modelDenyRead": ["~/.netrc"],      // Layer 2 only: model's read tool blocked; subprocesses ok
    "allowWrite": [".", "/tmp"],        // Layer 2: writes only inside these roots
    "denyWrite": [".env", "*.pem"]     // Layer 1 + Layer 2: write always blocked
  },
  "subagent": {
    "network": "allow"                  // "allow" | "deny" | "research-only"
  }
}
```

### Absolute-deny tier

Access to `~/.ssh`, `~/.gnupg`, `~/.aws`, `*.pem`, `*.key` is always a high-risk block. The prompt requires typing `"i understand"` verbatim and the "always" option is never offered.

## Commands

| Command | Description |
|---------|-------------|
| `/security` | Show Layer 2 policy, project-local overrides, last 10 audit events |
| `/sandbox` | Show Layer 1 (bash sandbox) config |
| `/sandbox reload` | Live-reload sandbox after manual edits to `sandbox.json` |

## Escape hatches

```bash
pi --yolo          # disables ALL layers globally (visible warning banner)
pi --no-sandbox    # alias for --yolo
```

## Audit log

Every block/allow/always decision is appended to `~/.pi/agent/audit.log` as a JSON line:

```jsonc
{
  "ts": "2026-07-15T10:00:00.000Z",
  "layer": 2,
  "tool": "write",
  "subject": "/Users/you/project/secret.pem",
  "reason": "denyWrite matched \"*.pem\"",
  "decision": "no",
  "cwd": "/Users/you/project"
}
```

## Development

```bash
git clone https://github.com/hannesro/pi-secure-it
cd pi-secure-it
npm install          # installs typescript for typecheck
npm run typecheck    # type-checks against pi's bundled .d.ts files
pi -e .              # load extension for the current session only
```

## Releasing

Releases are fully automated with [semantic-release](https://semantic-release.gitbook.io/), driven by [Conventional Commits](https://www.conventionalcommits.org/) on `main`:

- `fix: ...` → patch release
- `feat: ...` → minor release
- `feat!: ...` or a `BREAKING CHANGE:` footer → major release
- `chore:`, `docs:`, `refactor:`, `test:`, `ci:` etc. → no release by themselves

Commit messages on pull requests are checked by `commitlint` (`.github/workflows/commitlint.yml`). On every push to `main`, `.github/workflows/release.yml` runs `semantic-release`, which:

1. Determines the next version from commits since the last release.
2. Generates release notes and prepends them to `CHANGELOG.md`.
3. Publishes to npm (`npm publish --provenance`) and bumps `package.json`.
4. Creates the `vX.Y.Z` git tag and GitHub release.
5. Commits `CHANGELOG.md`/`package.json` back to `main` (`chore(release): ... [skip ci]`).

Nothing to run locally beyond writing conventional commit messages — just merge to `main`. Publishing uses npm [Trusted Publishing](https://docs.npmjs.com/trusted-publishers) (OIDC) — no `NPM_TOKEN` secret required. One-time setup on npmjs.com:

1. Go to the package's **Settings → Trusted Publisher** on npmjs.com.
2. Select **GitHub Actions** and configure: organization/user `hannesro`, repository `pi-secure-it`, workflow filename `release.yml`, allowed action `npm publish`.
3. (Recommended) Under **Settings → Publishing access**, choose "Require two-factor authentication and disallow tokens" to disable classic token-based publishing entirely, and revoke any automation tokens you previously created.

`GITHUB_TOKEN` is provided automatically by Actions; the `id-token: write` permission in `release.yml` is what lets npm's OIDC exchange work.

## License

MIT
