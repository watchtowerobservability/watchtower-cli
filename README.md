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
| Scoop | `scoop install https://github.com/watchtowerobservability/watchtower-cli/releases/latest/download/wtctl.json` |
| Download | the release page: `wtctl_<os>_<arch>` for linux, darwin and windows on amd64 and arm64, plus `SHA256SUMS` |
| Script (Linux, macOS) | see below |

```sh
os=$(uname -s | tr A-Z a-z); arch=$(uname -m); case $arch in x86_64) arch=amd64;; aarch64) arch=arm64;; esac
base=https://github.com/watchtowerobservability/watchtower-cli/releases/latest/download
curl -fsSLO "$base/wtctl_${os}_${arch}" && curl -fsSLO "$base/SHA256SUMS"
grep " wtctl_${os}_${arch}\$" SHA256SUMS | { command -v sha256sum >/dev/null && sha256sum -c - || shasum -a 256 -c -; } \
  && sudo install -m 0755 "wtctl_${os}_${arch}" /usr/local/bin/wtctl
```

## Version and updates

```sh
wtctl version            # wtctl 0.2.0 (linux/amd64, go1.26.0)
wtctl version --check    # compares with the latest GitHub release
wtctl self-update        # downloads the latest release binary for this OS/arch, verifies SHA256SUMS, replaces itself
```

`self-update` takes `--url <release location>` (or `$WTCTL_UPDATE_URL`) for a mirror that serves `SHA256SUMS` and the `wtctl_<os>_<arch>` assets; `--check` prints the checksum it would install. A Homebrew, Scoop or npm install is better updated with that package manager.

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
