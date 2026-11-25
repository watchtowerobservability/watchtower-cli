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

test('launcher forwards every argument and the exit code of the binary (wtctl and wt names)', () => {
  if (process.platform === 'win32') return; // the stub is a shebang script
  const fs = require('node:fs');
  const os = require('node:os');
  const path = require('node:path');
  const { spawnSync } = require('node:child_process');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wtlaunch-'));
  try {
    fs.mkdirSync(path.join(dir, 'bin'));
    fs.copyFileSync(path.join(__dirname, 'bin', 'wtctl.js'), path.join(dir, 'bin', 'wtctl.js'));
    const stub = path.join(dir, 'bin', 'wtctl-bin');
    fs.writeFileSync(stub, `#!${process.execPath}\nconsole.log(JSON.stringify(process.argv.slice(2)));process.exit(Number(process.env.STUB_EXIT||0));\n`, { mode: 0o755 });
    const args = ['activity', 'config', 'plan', '--file', 'a b.json', '--detailed-exitcode'];
    for (const code of ['0', '1', '2']) {
      const r = spawnSync(process.execPath, [path.join(dir, 'bin', 'wtctl.js'), ...args], { env: { ...process.env, STUB_EXIT: code }, encoding: 'utf8' });
      assert.strictEqual(r.status, Number(code));
      assert.deepStrictEqual(JSON.parse(r.stdout), args);
    }
    const bin = require('./package.json').bin;
    assert.strictEqual(bin.wt, bin.wtctl); // `wt` is a second name of the same launcher
    assert.strictEqual(bin.cli, bin.wtctl); // npx runs the bin named like the package when there are several
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

// One version everywhere: package.json (what install.js downloads), the CHANGELOG's top entry, and the
// binary's version string, which the release workflow injects from the same tag it publishes the package at.
test('package version, CHANGELOG top entry and release-built binary version agree', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8')).version;
  const log = fs.readFileSync(path.join(__dirname, '..', 'CHANGELOG.md'), 'utf8');
  const top = /^## \[?v?(\d+\.\d+\.\d+)\]?/m.exec(log)[1];
  assert.strictEqual(pkg, top, 'package.json version must equal the top CHANGELOG entry');
  const wf = fs.readFileSync(path.join(__dirname, '..', '.github', 'workflows', 'release.yml'), 'utf8');
  assert.match(wf, /VERSION=\$\{GITHUB_REF_NAME#v\}[\s\S]*-X main\.Version=\$VERSION/, 'binary version comes from the tag');
  assert.match(wf, /npm version "\$\{GITHUB_REF_NAME#v\}"/, 'npm version comes from the same tag');
  assert.match(wf, /CHANGELOG\.md/, 'release checks the CHANGELOG against the tag');
  const install = fs.readFileSync(path.join(__dirname, 'install.js'), 'utf8');
  assert.match(install, /require\('\.\/package\.json'\)\.version/, 'launcher downloads package.json version');
  assert.doesNotMatch(install, /\bv?\d+\.\d+\.\d+\b/, 'no hard-coded version in install.js');
});
