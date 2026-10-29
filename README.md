# watchtower-cli

`wtctl`, the Watchtower command line client: checks, dashboards, alert rules, datasets and evals as code,
source map and debug file upload, release markers, code instrumentation and the MCP stdio proxy for IDE agents.
It calls the public `/v1` API with your key; it contains no server logic.

## Install

| Method | Command |
|---|---|
| Homebrew | `brew install watchtowerobservability/tap/wtctl` |
| npm | `npm i -g @watchtowerobservability/cli` (downloads and SHA256-verifies the release binary; GitHub Packages registry) |
| Go | `go install github.com/watchtowerobservability/watchtower-cli/wtctl@latest` |
| Scoop | `scoop install https://raw.githubusercontent.com/watchtowerobservability/watchtower-cli/main/scoop/wtctl.json` |
| Download | the release page: `wtctl_<os>_<arch>` for linux, darwin and windows on amd64 and arm64, plus `SHA256SUMS` |

## Quick start

```sh
export WT_API_KEY=wtk_...
export WT_API_URL=https://watchtower.example.com
export WT_MCP_URL=https://watchtower.example.com/mcp
wtctl --help
wtctl mcp serve --stdio --project <id>
```

## Configuration

| Variable | Meaning |
|---|---|
| `WT_API_KEY` | API key, sent only as `Authorization: Bearer` to your Watchtower |
| `WT_API_URL` | API base URL |
| `WT_MCP_URL` | hosted MCP endpoint used by `wtctl mcp serve` |
| `GITHUB_TOKEN` | used by `wtctl instrument --open-pr` |

## Verify provenance

```sh
gh attestation verify wtctl_linux_amd64 --repo watchtowerobservability/watchtower-cli
sha256sum -c SHA256SUMS --ignore-missing
```

## License

Apache-2.0.
