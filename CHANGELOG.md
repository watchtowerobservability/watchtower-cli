# Changelog

## 0.5.0

- New `wtctl activity config plan|apply|get --file activity.json` (`-f` works too): the whole Activity project config (schemas, theme, policy, retention, alert rules, hooks, `secret_ref` names) as code. `plan --detailed-exitcode` (alias `--exit-code`) exits 0 when nothing changes, 2 on drift, 1 on an error; without the flag drift exits 0, like `wtctl plan`. `--json` prints exactly the server's plan document (the same as `config.plan()` in the Activity SDK). Runs with a project-scoped service-account key holding the scope `config:activity`.
- `activity config plan` prints the `retention` section and, for a theme change, one line per key (`theme  showMetadata: true → absent`, from the plan's `key_changes`; keys without a scalar value say `changed`), sorted, and every warning with its `code` (`warning [metadata_hidden]: ...`), so a CI log shows them. `--json` is still the server's document untouched.
- npm: the version of the package is the version of the binary it downloads: `npm/package.json`, the top entry of this file and the release tag must agree (a test and the release workflow check it).
- npm: the package installs the binary under two names, `wtctl` and `wt` (`wt activity config plan ...`), plus `cli` so that `npx` still finds its executable now that there are several. `npx @watchtowerobservability/cli activity config plan ...` passes every argument and the exit code through.

## 0.4.0

- `plan` and `diff` check every resource against the API's OpenAPI schema (unknown fields, missing required fields, bad enum values) before anything is written; a failed `apply` rolls back what it wrote and says `rolled back N change(s)`.
- `export` leaves out every top-level field the API's create body refuses (an SLO's `kind`, rule ids, receiver warnings, ...), so an export applies as written. Manifests exported by older versions may carry them: `plan` names each one.
- New `wtctl whoami [--json]` (what the key is and can reach, prefix only) and `wtctl health [--json] [--fail-on error|warning|never]` (the doctor checks plus telemetry, integrations and monitors of `WT_PROJECT`); `doctor --json`. Each check is `{id, status, detail, remedy}`.
- `plan --exit-code` is an alias of `--detailed-exitcode`.
- `--prune` deletes wtctl-managed catalog services.

- npm install: the expected SHA-256 of each binary is pinned inside the package (`checksums.json`, written at release by `npm/scripts/pin-checksums.mjs`) and checked instead of a `SHA256SUMS` fetched from the same place; without a pin for the version, the downloaded `SHA256SUMS` is used with a warning.
- npm install: `WTCTL_DOWNLOAD_BASE` must be https (http only for localhost/127.0.0.1) and prints a warning when set.
- The npm package now ships LICENSE and README.

## 0.3.3

- `-h` and `--help` print usage and exit 0 on every subcommand (they exited 1 with "flag: help requested").
- npm install: `WTCTL_DOWNLOAD_BASE` points the postinstall download at a mirror of the release assets, for runners that only reach the npm registry. Without it, the binary comes from `github.com` (redirected to `objects.githubusercontent.com`).

## 0.3.2

- `wtctl login`: sign in from the browser with a device code; no key to paste. `--scope bootstrap` gets a token that can create projects and keys but cannot read telemetry, for provisioning from CI. The token is saved owner-only (0600) in the wtctl config.
- `wtctl logout` removes the context and revokes its token when the server allows it.
- `apply` takes `Project` (created by slug when missing) and `ShapingRule` documents.

## 0.3.1

- As code converges: `apply` followed by `diff` reports `0 change(s)`; `write_token_to` works for every token kind (written 0600); `ServiceAccount` and the newer kinds apply.
- Routing documents name Receivers (`receiver: <name>`) at any depth, and `export` writes the names back.
- `export` drops server-owned fields (`next_eval_at`, `groups_truncated`, `warnings`, `muted_until`, `rebuilt_at`, `rebuild_error`) and writes singletons as `routing.yaml` / `orgsso.yaml`.
- `sourcemaps upload` takes everything from `WT_*` env and creates the release when it is missing; `diff` output no longer escapes `<` and `&`.

## 0.3.0

- `wtctl deps upload` sends the symbols your code uses, so the server can rank vulnerabilities by reachability. Servers that need this answer `426 client_too_old` to older clients; update with `wtctl self-update`.
- `wtctl scan`: taint analysis for Go, JavaScript and Python sources (a source reaching a sink), plus the `r.URL.Query()` source and Python sink-line fixes.
- `wtctl ci`: CI visibility commands and quality gates, synthetic checks with multi-browser fan-out.

## 0.2.0

- `wtctl version [--check]`: the release version (stamped at build time) and a check against the latest release.
- `wtctl self-update` defaults to the latest GitHub release and fetches the published asset names (`wtctl_<os>_<arch>`).
- `wtctl tests select`: Test Impact Analysis for CI (`--base origin/main`, `--format json|skip|run|go-skip`).
- `wtctl tests coverage upload|go`: per-test coverage from lcov (`TN:` records), a JSON map, or Go packages.
- The release attaches a Scoop manifest (`wtctl.json`) with the real hashes.

## 0.1.0

- First public release of `wtctl`, the Watchtower command line client.
- `wtctl mcp serve --stdio` is a stdio proxy to the hosted MCP endpoint (`WT_MCP_URL`).
