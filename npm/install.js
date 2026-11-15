'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { assetName, checkSum, pinnedSum, checkBase } = require('./lib');

async function get(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${url}: ${r.status}`);
  return Buffer.from(await r.arrayBuffer());
}

(async () => {
  const name = assetName(process.platform, process.arch);
  if (!name) throw new Error(`unsupported platform ${process.platform}/${process.arch}`);
  const v = require('./package.json').version;
  // WTCTL_DOWNLOAD_BASE: a mirror of the GitHub release assets, for runners that only reach npm.
  const custom = process.env.WTCTL_DOWNLOAD_BASE;
  if (custom) {
    checkBase(custom);
    console.warn(`wtctl install: downloading from WTCTL_DOWNLOAD_BASE=${custom}`);
  }
  const root = custom || 'https://github.com/watchtowerobservability/watchtower-cli/releases/download';
  const base = `${root.replace(/\/+$/, '')}/v${v}`;
  // checksums.json ships inside this package (written by scripts/pin-checksums.mjs at release), so a mirror cannot vouch for its own binary.
  let pins = null;
  try { pins = JSON.parse(fs.readFileSync(path.join(__dirname, 'checksums.json'), 'utf8')); } catch { /* not pinned */ }
  const pin = pinnedSum(pins, v, name);
  // fail closed: a hash fetched from the same host as the binary proves nothing
  if (!pin) throw new Error(`no pinned checksum for ${name} v${v} in this package (checksums.json missing or stale); refusing to install`);
  const bin = await get(`${base}/${name}`);
  checkSum(bin, pin, name);
  const dest = path.join(__dirname, 'bin', process.platform === 'win32' ? 'wtctl-bin.exe' : 'wtctl-bin');
  fs.writeFileSync(dest, bin, { mode: 0o755 });
})().catch((e) => {
  console.error(`wtctl install failed: ${e.message}`);
  process.exit(1);
});
