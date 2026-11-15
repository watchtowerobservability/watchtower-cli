// Release step: node scripts/pin-checksums.mjs <SHA256SUMS> [checksums.json]
// Reads the release's SHA256SUMS and writes checksums.json (this package's version + wtctl_* hashes) so install.js pins them.
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const [sums, out = join(root, 'checksums.json')] = process.argv.slice(2);
if (!sums) { console.error('usage: pin-checksums.mjs <SHA256SUMS> [checksums.json]'); process.exit(2); }
const assets = {};
for (const line of readFileSync(sums, 'utf8').split('\n')) {
  const [h, n] = line.trim().split(/\s+/);
  if (n && /^wtctl_/.test(n) && /^[0-9a-f]{64}$/i.test(h)) assets[n.replace(/^\*/, '')] = h.toLowerCase();
}
if (Object.keys(assets).length < 6) { console.error(`expected 6 wtctl_* assets, found ${Object.keys(assets).length}`); process.exit(1); }
const { version } = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
writeFileSync(out, JSON.stringify({ version, assets }, null, 2) + '\n');
console.log(`pinned ${Object.keys(assets).length} assets for v${version} -> ${out}`);
