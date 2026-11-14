'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { assetName, verify } = require('./lib');

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
  const root = process.env.WTCTL_DOWNLOAD_BASE || 'https://github.com/watchtowerobservability/watchtower-cli/releases/download';
  const base = `${root.replace(/\/+$/, '')}/v${v}`;
  const [bin, sums] = await Promise.all([get(`${base}/${name}`), get(`${base}/SHA256SUMS`)]);
  verify(bin, sums.toString(), name);
  const dest = path.join(__dirname, 'bin', process.platform === 'win32' ? 'wtctl-bin.exe' : 'wtctl-bin');
  fs.writeFileSync(dest, bin, { mode: 0o755 });
})().catch((e) => {
  console.error(`wtctl install failed: ${e.message}`);
  process.exit(1);
});
