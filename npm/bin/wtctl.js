#!/usr/bin/env node
'use strict';
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const exe = path.join(__dirname, process.platform === 'win32' ? 'wtctl-bin.exe' : 'wtctl-bin');
const r = spawnSync(exe, process.argv.slice(2), { stdio: 'inherit' });
if (r.error) {
  console.error(`wtctl: ${r.error.message}`);
  process.exit(1);
}
process.exit(r.status ?? 1);
