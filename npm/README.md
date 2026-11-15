# @watchtowerobservability/cli

The Watchtower command line client (`wtctl`) as an npm package. It is a thin wrapper: `npm install` downloads the release binary for your OS and CPU and refuses to install it unless its SHA-256 matches.

    npm i -g @watchtowerobservability/cli
    wtctl --help

## Verification

Each release ships the expected SHA-256 of every binary inside this package (`checksums.json`), so a changed download or a mirror cannot vouch for itself. A package version without `checksums.json` falls back to the release's `SHA256SUMS` and prints a warning. A mismatch exits 1 and installs nothing.

## Environment

- `WTCTL_DOWNLOAD_BASE`: mirror of the GitHub release assets (`<base>/v<version>/<asset>`), for runners that only reach npm. Must be `https` (`http` only for `localhost` / `127.0.0.1`). A warning is printed when it is set. The pinned checksum still applies.

Binaries come from `github.com/watchtowerobservability/watchtower-cli/releases` (redirected to `objects.githubusercontent.com`). Licensed under Apache-2.0.
