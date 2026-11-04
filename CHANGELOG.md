# Changelog

## 0.2.0

- `wtctl version [--check]`: the release version (stamped at build time) and a check against the latest release.
- `wtctl self-update` defaults to the latest GitHub release and fetches the published asset names (`wtctl_<os>_<arch>`).
- `wtctl tests select`: Test Impact Analysis for CI (`--base origin/main`, `--format json|skip|run|go-skip`).
- `wtctl tests coverage upload|go`: per-test coverage from lcov (`TN:` records), a JSON map, or Go packages.
- The release attaches a Scoop manifest (`wtctl.json`) with the real hashes.

## 0.1.0

- First public release of `wtctl`, the Watchtower command line client.
- `wtctl mcp serve --stdio` is a stdio proxy to the hosted MCP endpoint (`WT_MCP_URL`).
