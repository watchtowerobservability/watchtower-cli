'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { assetName, checkSum, pinnedSum, checkBase } = require('./lib');
// Shared by @watchtowerobservability/cli and /dev (copied into the dev mirror): the tool is the
// package's first bin and the release repository is package.json's "github:<org>/<repo>".
const { bin: bins, repository } = require('./package.json');
const tool = Object.keys(bins)[0];

async function get(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${url}: ${r.status}`);
  return Buffer.from(await r.arrayBuffer());
}

(async () => {
  const name = assetName(process.platform, process.arch, tool);
  if (!name) throw new Error(`unsupported platform ${process.platform}/${process.arch}`);
  const v = require('./package.json').version;
  // <TOOL>_DOWNLOAD_BASE (WTCTL_DOWNLOAD_BASE, WT_DEV_DOWNLOAD_BASE): a mirror of the GitHub release assets, for runners that only reach npm.
  const envName = `${tool.replace(/-/g, '_').toUpperCase()}_DOWNLOAD_BASE`;
  const custom = process.env[envName];
  if (custom) {
    checkBase(custom, envName);
    console.warn(`${tool} install: downloading from ${envName}=${custom}`);
  }
  const root = custom || `https://github.com/${repository.replace(/^github:/, '')}/releases/download`;
  const base = `${root.replace(/\/+$/, '')}/v${v}`;
  // checksums.json ships inside this package (written by scripts/pin-checksums.mjs at release), so a mirror cannot vouch for its own binary.
  let pins = null;
  try { pins = JSON.parse(fs.readFileSync(path.join(__dirname, 'checksums.json'), 'utf8')); } catch { /* not pinned */ }
  const pin = pinnedSum(pins, v, name);
  // fail closed: a hash fetched from the same host as the binary proves nothing
  if (!pin) throw new Error(`no pinned checksum for ${name} v${v} in this package (checksums.json missing or stale); refusing to install`);
  const bin = await get(`${base}/${name}`);
  checkSum(bin, pin, name);
  const dest = path.join(__dirname, 'bin', `${tool}-bin${process.platform === 'win32' ? '.exe' : ''}`);
  fs.writeFileSync(dest, bin, { mode: 0o755 });
})().catch((e) => {
  console.error(`${tool} install failed: ${e.message}`);
  process.exit(1);
});
