'use strict';
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
function loadScript(file) {
  const context = vm.createContext({});
  vm.runInContext(fs.readFileSync(path.resolve(__dirname, '../..', file), 'utf8') + '\napi = { main, ruleOptionsEnable };', context, { timeout: 4000 });
  return context.api;
}
module.exports = { loadScript };
