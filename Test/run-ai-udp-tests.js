#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const dgram = require('node:dgram');
const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');
const vm = require('node:vm');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const YAML = require('yaml');
const { generate } = require('../Tools/build-scripts');
const { cleanProxyEnvironment } = require('./lib/bettbox-core');

const projectRoot = path.resolve(__dirname, '..');
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const clone = value => JSON.parse(JSON.stringify(value));

async function freePort() {
  const server = net.createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

function receive(socket) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => finish(new Error('SOCKS handshake timed out')), 2000);
    function finish(error, data) {
      clearTimeout(timer);
      socket.off('data', onData);
      socket.off('error', onError);
      error ? reject(error) : resolve(data);
    }
    const onData = data => finish(null, data);
    const onError = error => finish(error);
    socket.once('data', onData);
    socket.once('error', onError);
  });
}

function productionConfig() {
  const context = vm.createContext({});
  vm.runInContext(generate(projectRoot), context, { timeout: 4000 });
  return clone(context.main({ proxies: [{ name: '美国 US TCP-only', type: 'socks5', server: '127.0.0.1', port: 9, udp: false }] }));
}

async function runCase({ binary, directory, production, originPort, guarded, arrivals }) {
  const name = guarded ? 'with-guard' : 'without-guard';
  const caseDirectory = path.join(directory, name);
  fs.mkdirSync(caseDirectory, { recursive: true });
  const aiIndex = production.rules.indexOf('SUB-RULE,(RULE-SET,ai),sub-ai');
  assert(aiIndex >= 0, 'Production AI rule is missing');
  const guard = production.rules[aiIndex + 1];
  assert(guard?.endsWith(',REJECT') && guard.includes('(NETWORK,UDP)') && guard.includes('(RULE-SET,ai)'), 'Production AI rule must be immediately followed by its UDP rejection guard');
  const aiGroup = clone(production['proxy-groups'].find(group => group.name === '国外AI'));
  const quicGroup = clone(production['proxy-groups'].find(group => group.name === '代理QUIC'));
  assert(aiGroup && quicGroup, 'Production service groups are missing');
  const nodeProvider = clone(production['proxy-providers']['节点']);
  nodeProvider['health-check'] = { enable: false };
  const subAi = clone(production['sub-rules']['sub-ai']);
  assert(subAi.some(rule => rule.includes('(DST-PORT,443)')), 'Upstream AI QUIC structure changed');
  // Exercise the production PASS-RULE branch on an unprivileged, isolated UDP port.
  const localSubAi = subAi.map(rule => rule.replace('(DST-PORT,443)', '(DST-PORT,' + originPort + ')'));
  const mixedPort = await freePort();
  const controllerPort = await freePort();
  const secret = crypto.randomUUID();
  const config = {
    'mixed-port': mixedPort,
    'allow-lan': false,
    'bind-address': '127.0.0.1',
    'external-controller': '127.0.0.1:' + controllerPort,
    secret,
    mode: 'rule',
    'log-level': 'debug',
    ipv6: false,
    hosts: { 'fixed-ai.test': '127.0.0.1', 'other-service.test': '127.0.0.1' },
    dns: { enable: true, ipv6: false, 'use-hosts': true, nameserver: ['127.0.0.1:9'] },
    'proxy-providers': { 节点: nodeProvider },
    'proxy-groups': [aiGroup, quicGroup, { name: 'Review fallback', type: 'select', proxies: ['DIRECT'] }],
    'rule-providers': { ai: { type: 'inline', behavior: 'domain', format: 'text', payload: ['fixed-ai.test'] } },
    'sub-rules': { 'sub-ai': localSubAi },
    rules: [production.rules[aiIndex], ...(guarded ? [guard] : []), 'MATCH,Review fallback'],
  };
  const configPath = path.join(caseDirectory, 'config.yaml');
  fs.writeFileSync(configPath, YAML.stringify(config));
  const child = spawn(binary, ['-d', caseDirectory, '-f', configPath], { windowsHide: true, env: cleanProxyEnvironment(), stdio: ['ignore', 'pipe', 'pipe'] });
  let logs = '', launchError, tcp, udp;
  child.on('error', error => { launchError = error; });
  for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => { logs = (logs + chunk).slice(-80000); });
  const control = (route, method = 'GET', body) => new Promise((resolve, reject) => {
    const request = http.request({ host: '127.0.0.1', port: controllerPort, path: route, method, agent: false, headers: { Authorization: 'Bearer ' + secret, 'Content-Type': 'application/json' } }, response => {
      let text = '';
      response.on('data', chunk => { text += chunk; });
      response.on('end', () => {
        if (response.statusCode >= 400) return reject(new Error('Controller HTTP ' + response.statusCode));
        try { resolve(text ? JSON.parse(text) : null); } catch (error) { reject(error); }
      });
    });
    request.on('error', reject);
    request.setTimeout(1000, () => request.destroy(new Error('Controller timeout')));
    request.end(body === undefined ? undefined : JSON.stringify(body));
  });
  try {
    let ready = false;
    for (let attempt = 0; attempt < 60; attempt++) {
      if (launchError) throw launchError;
      if (child.exitCode !== null) throw new Error('Mihomo exited: ' + logs);
      try {
        const providers = await control('/providers/rules');
        if (providers.providers.ai?.ruleCount > 0) { ready = true; break; }
      } catch {}
      await pause(100);
    }
    assert(ready, 'Mihomo providers did not initialize: ' + logs);
    await control('/proxies/' + encodeURIComponent('国外AI'), 'PUT', { name: '美国 US TCP-only' });
    await control('/proxies/' + encodeURIComponent('代理QUIC'), 'PUT', { name: 'PASS-RULE' });
    tcp = net.createConnection(mixedPort, '127.0.0.1');
    await once(tcp, 'connect');
    let reply = receive(tcp);
    tcp.write(Buffer.from([5, 1, 0]));
    assert.deepEqual(await reply, Buffer.from([5, 0]));
    reply = receive(tcp);
    tcp.write(Buffer.from([5, 3, 0, 1, 0, 0, 0, 0, 0, 0]));
    const association = await reply;
    assert.equal(association[1], 0, 'SOCKS UDP association failed');
    assert.equal(association[3], 1, 'Expected IPv4 SOCKS relay');
    const relayPort = association.readUInt16BE(8);
    udp = dgram.createSocket('udp4');
    udp.bind(0, '127.0.0.1');
    await once(udp, 'listening');
    function send(domain, payload) {
      const host = Buffer.from(domain), port = Buffer.alloc(2);
      port.writeUInt16BE(originPort);
      const packet = Buffer.concat([Buffer.from([0, 0, 0, 3, host.length]), host, port, Buffer.from(payload)]);
      udp.send(packet, relayPort, '127.0.0.1');
    }
    const aiPayload = name + ':ai';
    send('fixed-ai.test', aiPayload);
    await pause(600);
    if (guarded) assert(!arrivals.includes(aiPayload), 'AI UDP escaped its fixed exit');
    else assert(arrivals.includes(aiPayload), 'Negative control did not demonstrate UDP fallback');
    const otherPayload = name + ':other';
    send('other-service.test', otherPayload);
    for (let attempt = 0; attempt < 20 && !arrivals.includes(otherPayload); attempt++) await pause(50);
    assert(arrivals.includes(otherPayload), 'Guard must not block unrelated UDP traffic');
    assert(logs.includes('UDP is not supported'), 'Selected AI node must be the reason the first rule is skipped');
    if (guarded) assert(logs.includes('using REJECT'), 'Guard must reject the AI datagram');
    return { guarded, aiDelivered: arrivals.includes(aiPayload), otherDelivered: arrivals.includes(otherPayload), guard };
  } finally {
    tcp?.destroy();
    udp?.close();
    if (child.exitCode === null && child.pid) { const exited = once(child, 'exit'); child.kill(); await exited; }
    fs.writeFileSync(path.join(caseDirectory, 'core.log'), logs);
    fs.unlinkSync(configPath);
  }
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length !== 2 || args[0] !== '--mihomo') throw new Error('Usage: node Test/run-ai-udp-tests.js --mihomo <official Mihomo executable>');
  const binary = path.resolve(args[1]);
  assert(fs.existsSync(binary), 'Mihomo executable does not exist');
  const directory = path.join(projectRoot, '.test-runtime', 'ai-udp-' + crypto.randomUUID());
  fs.mkdirSync(directory, { recursive: true });
  const receiver = dgram.createSocket('udp4'), arrivals = [], results = [];
  receiver.on('message', (message, peer) => { arrivals.push(message.toString()); receiver.send(message, peer.port, peer.address); });
  receiver.bind(0, '127.0.0.1');
  await once(receiver, 'listening');
  try {
    const production = productionConfig();
    for (const guarded of [false, true]) results.push(await runCase({ binary, directory, production, originPort: receiver.address().port, guarded, arrivals }));
    console.log('PASS negative control: an AI node without UDP support falls through to another exit.');
    console.log('PASS production guard: AI UDP is rejected; unrelated UDP still reaches its destination.');
  } finally {
    receiver.close();
    fs.writeFileSync(path.join(directory, 'results.json'), JSON.stringify({ passed: results.length === 2, results, arrivals }, null, 2));
  }
}
main().catch(error => { console.error(error.stack); process.exitCode = 1; });
