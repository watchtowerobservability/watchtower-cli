# Changelog

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
