#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const YAML = require('yaml');
const { loadScript } = require('./lib/loader');
const { fixtures, freePort } = require('./lib/network-fixtures');
const { cleanProxyEnvironment } = require('./lib/bettbox-core');

async function main() {
  const args = process.argv.slice(2);
  if (args.length !== 2 || args[0] !== '--mihomo') throw new Error('Usage: --mihomo <official Mihomo executable>');
  const binary = path.resolve(args[1]);
  const directory = path.resolve('.test-runtime', 'rule-routing-' + crypto.randomUUID());
  fs.mkdirSync(directory, { recursive: true });
  const fx = await fixtures();
  let fixturesClosed = false;
  try {
  const cases = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/routing-cases.json'), 'utf8'));
  const api = loadScript('Script/mihomoScript.js');
  const cfg = api.main(fx.subscription());
  const sources = JSON.parse(fs.readFileSync('config/rule-sources.json', 'utf8')).rulesets;
  fs.mkdirSync(path.join(directory, 'rules'), { recursive: true });
  // Load all generated sets, including optional services, into the real decoder.
  for (const [id, item] of Object.entries(sources)) {
    const file = path.join(directory, 'rules', id + '.mrs');
    fs.copyFileSync(path.resolve('Rules/generated', item.behavior, id + '.mrs'), file);
    cfg['rule-providers'][id] = { type: 'file', behavior: item.behavior, format: 'mrs', path: file };
  }
  const port = await freePort(), controller = await freePort(), secret = crypto.randomUUID();
  Object.assign(cfg, { 'mixed-port': port, 'allow-lan': false, 'bind-address': '127.0.0.1', 'external-controller': '127.0.0.1:' + controller, secret, tun: { enable: false }, ntp: { enable: false }, 'external-ui': '', 'external-ui-url': '', ipv6: false });
  cfg.dns = { enable: true, ipv6: false, 'use-hosts': true, nameserver: ['127.0.0.1:' + fx.udpPort] };
  for (const item of cases) cfg.hosts[item.domain] = '127.0.0.1';
  for (const group of cfg['proxy-groups']) { group.interval = 0; group.lazy = true; }
  fs.writeFileSync(path.join(directory, 'config.yaml'), YAML.stringify(cfg));
  let child, logs = '';
  const results = [];
  let completed = false;
  const control = (route, method = 'GET', body) => new Promise((resolve, reject) => {
    const request = http.request({ hostname: '127.0.0.1', port: controller, path: route, method, headers: { Authorization: 'Bearer ' + secret, 'Content-Type': 'application/json' }, agent: false }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => {
        if (response.statusCode >= 400) return reject(new Error('Controller HTTP ' + response.statusCode));
        try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : null); } catch (error) { reject(error); }
      });
    });
    request.on('error', reject);
    request.setTimeout(2000, () => request.destroy(new Error('Controller timeout')));
    request.end(body === undefined ? undefined : JSON.stringify(body));
  });
  try {
    child = spawn(binary, ['-d', directory, '-f', path.join(directory, 'config.yaml')], { windowsHide: true, env: cleanProxyEnvironment(), stdio: ['ignore', 'pipe', 'pipe'] });
    let launchError;
    child.on('error', error => { launchError = error; });
    for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => { logs = (logs + chunk).slice(-80000); });
    let ready = false;
    for (let attempt = 0; attempt < 60; attempt++) {
      if (launchError) throw launchError;
      if (child.exitCode !== null) throw new Error('Mihomo exited: ' + logs.slice(-1500));
      try { await control('/version'); ready = true; break; } catch { await new Promise(resolve => setTimeout(resolve, 100)); }
    }
    if (!ready) throw new Error('Mihomo did not start: ' + logs.slice(-1500));
    for (const [group, node] of Object.entries({ 代理连接: 'HK 01', GOOGLE: '代理连接', 国外AI: 'US 01' })) {
      await control('/proxies/' + encodeURIComponent(group), 'PUT', { name: node });
    }
    // Providers initialize asynchronously; require the complete set before requests.
    let providers;
    for (let attempt = 0; attempt < 60; attempt++) {
      providers = (await control('/providers/rules')).providers;
      if (Object.keys(sources).every(id => providers[id]?.ruleCount > 0)) break;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    assert(Object.keys(sources).every(id => providers[id]?.ruleCount > 0), 'All generated MRS sets must decode');
    for (const item of cases) {
      let request, response;
      try {
        await new Promise((resolve, reject) => {
          request = http.get({ hostname: '127.0.0.1', port, path: `http://${item.domain}:${fx.origin.port}/hold`, headers: { Host: item.domain + ':' + fx.origin.port }, agent: false }, result => {
            response = result;
            response.on('error', () => {});
            response.once('data', () => resolve());
            response.resume();
          });
          request.on('error', reject);
          request.setTimeout(4000, () => request.destroy(new Error('Route request timed out')));
        });
        const active = await control('/connections');
        const connection = active.connections.find(c => c.metadata.host === item.domain);
        assert(connection, item.domain + ': connection metadata missing');
        assert(connection.chains.includes(item.expectedPolicy), `${item.domain}: expected ${item.expectedPolicy}, got ${connection.chains.join(' -> ')}`);
        const parts = item.expectedRule.split(',');
        const expectedType = { 'RULE-SET': 'RuleSet', 'DOMAIN': 'Domain', 'DOMAIN-SUFFIX': 'DomainSuffix', 'SUB-RULE': 'SubRules' }[parts[0]];
        const expectedPayload = parts[0] === 'SUB-RULE' ? item.expectedRule.slice(9, item.expectedRule.lastIndexOf(',')) : parts[1];
        assert.equal(connection.rule, expectedType, item.domain + ': rule type');
        assert.equal(connection.rulePayload, expectedPayload, item.domain + ': rule payload');
        results.push({ ...item, chains: connection.chains, rule: connection.rule, rulePayload: connection.rulePayload });
        console.log('PASS ' + item.domain + ' -> ' + item.expectedPolicy);
      } finally { request?.destroy(); response?.destroy(); }
    }
    if (process.platform === 'win32') {
      const copiedNode = path.join(directory, 'OneDrive.exe');
      fs.copyFileSync(process.execPath, copiedNode);
      const clientCode = `const http=require('node:http'); const req=http.get({hostname:'127.0.0.1',port:${port},path:'http://chatgpt.com:${fx.origin.port}/hold',headers:{Host:'chatgpt.com:${fx.origin.port}'},agent:false},res=>{res.once('data',()=>process.stdout.write('ready'));res.resume()});req.on('error',()=>process.exit(1));req.setTimeout(4000,()=>process.exit(1));`;
      try {
        for (const [executable, expected] of [[copiedNode, 'OneDrive'], [process.execPath, '国外AI']]) {
          const client = spawn(executable, ['-e', clientCode], { windowsHide: true, env: cleanProxyEnvironment(), stdio: ['ignore', 'pipe', 'ignore'] });
          let timer;
          try {
            await Promise.race([once(client.stdout, 'data'), once(client, 'exit').then(() => { throw new Error('Process client exited'); }), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Process client timeout')), 5000); })]);
            const connection = (await control('/connections')).connections.find(c => c.metadata.host === 'chatgpt.com' && c.chains.includes(expected));
            assert(connection, 'Windows process must route through ' + expected);
            assert.equal(connection.rule, expected === 'OneDrive' ? 'ProcessName' : 'SubRules');
            console.log('PASS Windows process ' + path.basename(executable) + ' -> ' + expected);
          } finally {
            clearTimeout(timer);
            if (client.exitCode === null) { const exited = once(client, 'exit'); client.kill(); await exited; }
          }
        }
      } finally { fs.unlinkSync(copiedNode); }
    }
    console.log(`Loaded ${Object.keys(sources).length} MRS sets; ${results.length} real-rule routes passed.`);
    completed = true;
  } finally {
    if (child && child.exitCode === null && child.pid) { const exited = once(child, 'exit'); child.kill(); await exited; }
    await fx.close();
    fixturesClosed = true;
    fs.writeFileSync(path.resolve('.test-runtime/rule-routing-results.json'), JSON.stringify({ results, passed: completed }, null, 2));
    fs.writeFileSync(path.join(directory, 'core.log'), logs);
    fs.unlinkSync(path.join(directory, 'config.yaml'));
  }
  } finally {
    if (!fixturesClosed) await fx.close();
  }
}
main().catch(error => { console.error(error.stack); process.exitCode = 1; });
