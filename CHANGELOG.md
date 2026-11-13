# Changelog

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
