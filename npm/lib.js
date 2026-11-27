'use strict';
const crypto = require('node:crypto');

// Release asset name for a Node platform/arch, or null when unsupported. The separator is the
// tool's own: wtctl_linux_amd64, wt-dev-linux-amd64.
function assetName(platform, arch, tool = 'wtctl') {
  const os = { linux: 'linux', darwin: 'darwin', win32: 'windows' }[platform];
  const cpu = { x64: 'amd64', arm64: 'arm64' }[arch];
  if (!os || !cpu) return null;
  const sep = tool.includes('-') ? '-' : '_';
  return `${tool}${sep}${os}${sep}${cpu}${os === 'windows' ? '.exe' : ''}`;
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
  checkSum(buf, expectedSum(sums, name), name);
}

function checkSum(buf, want, name) {
  if (!want) throw new Error(`no checksum for ${name}`);
  const got = crypto.createHash('sha256').update(buf).digest('hex');
  if (got !== want) throw new Error(`checksum mismatch for ${name}`);
}

// The pinned SHA256 for name from a parsed checksums.json ({version, assets}) for this package version, or null.
function pinnedSum(pins, version, name) {
  return pins && pins.version === version && pins.assets && pins.assets[name] ? String(pins.assets[name]).toLowerCase() : null;
}

// Throws unless the download base is https (plain http only for loopback, for tests).
function checkBase(root, env = 'WTCTL_DOWNLOAD_BASE') {
  let u;
  try { u = new URL(root); } catch { throw new Error(`${env} is not a URL: ${root}`); }
  const loopback = u.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
  if (u.protocol !== 'https:' && !loopback) throw new Error(`${env} must be an https URL`);
}

module.exports = { assetName, expectedSum, verify, checkSum, pinnedSum, checkBase };
