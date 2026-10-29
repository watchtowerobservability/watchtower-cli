'use strict';
const crypto = require('node:crypto');

// Release asset name for a Node platform/arch, or null when unsupported.
function assetName(platform, arch) {
  const os = { linux: 'linux', darwin: 'darwin', win32: 'windows' }[platform];
  const cpu = { x64: 'amd64', arm64: 'arm64' }[arch];
  if (!os || !cpu) return null;
  return `wtctl_${os}_${cpu}${os === 'windows' ? '.exe' : ''}`;
}

// The SHA256 listed for name in a `sha256sum` style file, or null.
function expectedSum(sums, name) {
  for (const line of sums.split('\n')) {
    const [h, n] = line.trim().split(/\s+/);
    if (n === name) return h;
  }
  return null;
}

function verify(buf, sums, name) {
  const want = expectedSum(sums, name);
  if (!want) throw new Error(`no checksum for ${name}`);
  const got = crypto.createHash('sha256').update(buf).digest('hex');
  if (got !== want) throw new Error(`checksum mismatch for ${name}`);
}

module.exports = { assetName, expectedSum, verify };
