'use strict';
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { assetName, expectedSum, verify, pinnedSum, checkBase } = require('./lib');

test('assetName', () => {
  assert.strictEqual(assetName('win32', 'x64'), 'wtctl_windows_amd64.exe');
  assert.strictEqual(assetName('darwin', 'arm64'), 'wtctl_darwin_arm64');
  assert.strictEqual(assetName('freebsd', 'x64'), null);
});

test('verify accepts a match and rejects tampering', () => {
  const buf = Buffer.from('binary');
  const h = crypto.createHash('sha256').update(buf).digest('hex');
  const sums = `${h}  wtctl_linux_amd64\n`;
  assert.strictEqual(expectedSum(sums, 'wtctl_linux_amd64'), h);
  verify(buf, sums, 'wtctl_linux_amd64');
  assert.throws(() => verify(Buffer.from('x'), sums, 'wtctl_linux_amd64'), /mismatch/);
  assert.throws(() => verify(buf, sums, 'other'), /no checksum/);
});

test('pinnedSum matches only this version; checkBase demands https (loopback http ok)', () => {
  const pins = { version: '1.0.0', assets: { a: 'AB' } };
  assert.strictEqual(pinnedSum(pins, '1.0.0', 'a'), 'ab');
  assert.strictEqual(pinnedSum(pins, '1.0.1', 'a'), null);
  assert.strictEqual(pinnedSum(null, '1.0.0', 'a'), null);
  checkBase('https://mirror.example/x');
  checkBase('http://localhost:8080');
  checkBase('http://127.0.0.1:1');
  assert.throws(() => checkBase('http://mirror.example'), /https/);
  assert.throws(() => checkBase('nonsense'), /not a URL/);
});

test('install.js: pinned hash beats a lying mirror; mismatch exits 1', async () => {
  const http = require('node:http');
  const fs = require('node:fs');
  const os = require('node:os');
  const path = require('node:path');
  const { spawn } = require('node:child_process');
  const name = assetName(process.platform, process.arch);
  const v = require('./package.json').version;
  const bin = Buffer.from('evil');
  const lie = crypto.createHash('sha256').update(bin).digest('hex');
  const srv = http.createServer((q, r) => r.end(q.url.endsWith('SHA256SUMS') ? `${lie}  ${name}\n` : bin)).listen(0, '127.0.0.1');
  await new Promise((r) => srv.on('listening', r));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wtcli-'));
  for (const f of ['install.js', 'lib.js', 'package.json']) fs.copyFileSync(path.join(__dirname, f), path.join(dir, f));
  fs.mkdirSync(path.join(dir, 'bin'));
  const env = { ...process.env, WTCTL_DOWNLOAD_BASE: `http://127.0.0.1:${srv.address().port}` };
  const run = () => new Promise((res) => { let err = ''; const c = spawn(process.execPath, [path.join(dir, 'install.js')], { env }); c.stderr.on('data', (d) => (err += d)); c.on('close', (code) => res({ code, err })); });
  try {
    fs.writeFileSync(path.join(dir, 'checksums.json'), JSON.stringify({ version: v, assets: { [name]: '0'.repeat(64) } }));
    const bad = await run();
    assert.strictEqual(bad.code, 1);
    assert.match(bad.err, /mismatch/);
    fs.rmSync(path.join(dir, 'checksums.json'));
    const unpinned = await run(); // fail closed even when the mirror's own SHA256SUMS agrees
    assert.strictEqual(unpinned.code, 1);
    assert.match(unpinned.err, /no pinned checksum/);
    fs.writeFileSync(path.join(dir, 'checksums.json'), JSON.stringify({ version: v, assets: { [name]: lie } }));
    assert.strictEqual((await run()).code, 0);
  } finally { srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});
