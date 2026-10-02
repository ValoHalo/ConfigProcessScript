#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const repository = process.argv[2];
const branch = process.argv[3] || 'main';
if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository || '') || !/^[A-Za-z0-9_./-]+$/.test(branch) || branch.includes('..')) {
  console.error('Usage: node Tools/configure-repository.js owner/repository [branch]');
  process.exitCode = 1;
} else {
  fs.writeFileSync(path.resolve(__dirname, '../config/project.json'), JSON.stringify({ repository, branch }, null, 2) + '\n');
  console.log('Rule publication repository: ' + repository + ' (' + branch + ')');
}
