#!/usr/bin/env node
'use strict';
const path = require('node:path');
const { spawn } = require('node:child_process');

// The binary sits next to this launcher as <launcher name>-bin (wtctl-bin; wt-dev-bin in @watchtowerobservability/dev).
const tool = path.basename(__filename, '.js');
const exe = path.join(__dirname, `${tool}-bin${process.platform === 'win32' ? '.exe' : ''}`);
const child = spawn(exe, process.argv.slice(2), { stdio: 'inherit' });
// a long-running command (wt-dev, wtctl mcp serve) must stop when the launcher is told to
for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(sig, () => child.kill(sig));
child.on('error', (e) => {
  console.error(`${tool}: ${e.message}`);
  process.exit(1);
});
child.on('exit', (code) => process.exit(code ?? 1));
