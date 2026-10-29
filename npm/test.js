'use strict';
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { assetName, expectedSum, verify } = require('./lib');

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
