#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const net = require('node:net');
const YAML = require('yaml');
const { loadScript } = require('./lib/loader');
const { BettboxCore, defaultCorePath } = require('./lib/bettbox-core');
const { freePort } = require('./lib/network-fixtures');
const { probe } = require('../Tools/probe-proxy');

async function main() {
  const args = process.argv.slice(2);
  if (args.length !== 2 || args[0] !== '--subscription') throw new Error('Usage: --subscription <local subscription YAML>');
  const filename = path.resolve(args[1]), source = fs.readFileSync(filename);
  const hash = crypto.createHash('sha256').update(source).digest('hex');
  const directory = path.resolve('.test-runtime', 'live-' + crypto.randomUUID());
  const config = loadScript('Script/mihomoScript.js').main(YAML.parse(source.toString('utf8')));
  const port = await freePort();
  const report = { checks: [], passed: false };
  fs.mkdirSync(path.join(directory, 'rules'), { recursive: true });
  for (const [id, provider] of Object.entries(config['rule-providers'])) {
    if (provider.type === 'inline') continue;
    const original = path.resolve('Rules/generated', provider.behavior, id + '.mrs');
    if (!fs.existsSync(original)) throw new Error('No generated local rules for ' + id);
    const copied = path.join(directory, 'rules', id + '.mrs'); fs.copyFileSync(original, copied);
    config['rule-providers'][id] = { type: 'file', format: 'mrs', behavior: provider.behavior, path: copied };
  }
  Object.assign(config, { 'mixed-port': port, 'allow-lan': false, 'bind-address': '127.0.0.1', tun: { enable: false }, ntp: { enable: false }, 'external-controller': '127.0.0.1:' + await freePort(), secret: crypto.randomUUID(), 'external-ui': '', 'external-ui-url': '', 'log-level': 'info' });
  // Ensure the generic health URL exercises the selected AI node, even when
  // upstream Apple rules normally select a direct connection.
  config.rules.unshift('DOMAIN,www.apple.com,国外AI');
  for (const group of config['proxy-groups']) { group.interval = 0; group.lazy = true; }
  for (const provider of Object.values(config['proxy-providers'])) if (provider['health-check']) provider['health-check'].enable = false;
  const core = new BettboxCore(defaultCorePath(), directory);
  try {
    await core.start(); await core.load(config);
    for (let attempt = 0; ; attempt++) {
      try {
        await new Promise((resolve, reject) => {
          const socket = net.connect({ host: '127.0.0.1', port });
          socket.once('connect', () => { socket.destroy(); resolve(); });
          socket.once('error', reject);
        });
        break;
      } catch (error) {
        if (attempt >= 29) throw new Error('Isolated proxy listener did not become ready');
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    }
    const groups = await core.call('getProxies');
    const availableNames = (groups['国外AI'].all || []).filter(name => name !== 'REJECT');
    const settings = JSON.parse(fs.readFileSync('Rules/personal/settings.json', 'utf8'));
    const ordered = [];
    for (const region of settings.ai.regions) {
      const group = config['proxy-groups'].find(g => g.name === region + '|故障转移');
      const match = new RegExp(group.filter.replace(/^\(\?i\)/, ''), 'i');
      for (const name of availableNames) if (match.test(name) && !ordered.includes(name)) ordered.push(name);
    }
    const candidates = ordered.slice(0, 3);
    let connected = false;
    for (const [index, node] of candidates.entries()) {
      await core.select('代理连接', node); await core.select('国外AI', node);
      try {
        const result = await probe({ url: 'https://www.apple.com/library/test/success.html', proxy: 'http://127.0.0.1:' + port, timeout: 12000 });
        report.checks.push({ case: 'AI candidate ' + (index + 1), status: result.status });
        if (result.status === 200) { connected = true; break; }
      } catch (error) { report.checks.push({ case: 'AI candidate ' + (index + 1), error: error.message }); }
    }
    if (!connected) throw new Error('No tested AI candidate completed HTTPS');
    for (const [name, url] of [['AI', 'https://chatgpt.com/robots.txt'], ['DLsite', 'https://www.dlsite.com/']]) {
      try {
        const result = await probe({ url, proxy: 'http://127.0.0.1:' + port, timeout: 15000 });
        report.checks.push({ case: name, status: result.status });
      } catch (error) { report.checks.push({ case: name, error: error.message }); }
    }
    report.sourceUnchanged = crypto.createHash('sha256').update(fs.readFileSync(filename)).digest('hex') === hash;
    report.dlsiteDefault = groups.DLsite.now;
    report.passed = connected && report.sourceUnchanged && report.checks.filter(c => ['AI', 'DLsite'].includes(c.case)).every(c => c.status >= 200 && c.status < 400);
  } finally {
    report.sourceUnchanged = crypto.createHash('sha256').update(fs.readFileSync(filename)).digest('hex') === hash;
    fs.writeFileSync(path.join(directory, 'core.log'), core.logs);
    await core.stop();
    const temporary = path.join(directory, 'config.yaml'); if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
    fs.writeFileSync(path.resolve('.test-runtime/live-results.json'), JSON.stringify(report, null, 2));
    console.log(JSON.stringify(report, null, 2));
  }
  if (!report.passed) process.exitCode = 1;
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
