#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const http = require('node:http');
const dgram = require('node:dgram');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const YAML = require('yaml');
const { fixtures, freePort } = require('./lib/network-fixtures');
const { cleanProxyEnvironment } = require('./lib/bettbox-core');

const projectRoot = path.resolve(__dirname, '..');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

function buildConfig(subscription, mode, options) {
  const source = fs.readFileSync(path.join(projectRoot, 'Script/mihomoScript.js'), 'utf8');
  const context = vm.createContext({ subscription, mode, options });
  vm.runInContext(source + '\npersonalSettings.dns.ecsMode = mode; Object.assign(ruleOptionsEnable, options); output = main(subscription);', context, { timeout: 4000 });
  return JSON.parse(JSON.stringify(context.output));
}

// Send a normal application DNS request to the core's UDP listener. The
// controller /dns/query resolves real addresses and cannot prove Fake-IP mode.
async function queryUdp(port, name) {
  const id = crypto.randomInt(65536);
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id); header.writeUInt16BE(0x0100, 2); header.writeUInt16BE(1, 4);
  const question = Buffer.concat(name.split('.').map(label => Buffer.concat([Buffer.from([label.length]), Buffer.from(label)])));
  const query = Buffer.concat([header, question, Buffer.from([0, 0, 1, 0, 1])]);
  const socket = dgram.createSocket('udp4');
  try {
    return await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('DNS UDP query timed out: ' + name)), 4000);
      socket.once('error', error => { clearTimeout(timer); reject(error); });
      socket.once('message', message => {
        clearTimeout(timer);
        try {
          assert.equal(message.readUInt16BE(0), id);
          const skipName = start => {
            let offset = start;
            while (message[offset]) {
              if ((message[offset] & 0xc0) === 0xc0) return offset + 2;
              offset += message[offset] + 1;
            }
            return offset + 1;
          };
          let offset = 12;
          for (let n = message.readUInt16BE(4); n; n--) offset = skipName(offset) + 4;
          const addresses = [];
          for (let n = message.readUInt16BE(6); n; n--) {
            offset = skipName(offset);
            const type = message.readUInt16BE(offset), length = message.readUInt16BE(offset + 8);
            offset += 10;
            if (type === 1 && length === 4) addresses.push([...message.subarray(offset, offset + 4)].join('.'));
            offset += length;
          }
          resolve({ rcode: message.readUInt16BE(2) & 15, addresses });
        } catch (error) { reject(error); }
      });
      socket.send(query, port, '127.0.0.1', error => { if (error) { clearTimeout(timer); reject(error); } });
    });
  } finally { socket.close(); }
}

function controller(port, secret) {
  return (route, method = 'GET', body) => new Promise((resolve, reject) => {
    const request = http.request({ hostname: '127.0.0.1', port, path: route, method, headers: { Authorization: 'Bearer ' + secret, 'Content-Type': 'application/json' }, agent: false }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => {
        if (response.statusCode >= 400) return reject(new Error('Controller HTTP ' + response.statusCode + ': ' + Buffer.concat(chunks)));
        try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : null); } catch (error) { reject(error); }
      });
    });
    request.on('error', reject);
    request.setTimeout(5000, () => request.destroy(new Error('Controller timed out')));
    request.end(body === undefined ? undefined : JSON.stringify(body));
  });
}

async function runCase(binary, mode, parentDirectory, options = {}) {
  const optionalApps = Boolean(options.Apple);
  const directory = path.join(parentDirectory, mode + (optionalApps ? '-optional-apps' : ''));
  fs.mkdirSync(directory, { recursive: true });
  const nodeDomain = 'private-node.example.test';
  const fx = await fixtures({ dnsAddress: name => name === nodeDomain ? '127.0.0.1' : '203.0.113.7' });
  const subscription = fx.subscription();
  subscription.proxies[0].server = nodeDomain;
  subscription.dns = { 'proxy-server-nameserver': [`http://127.0.0.1:${fx.origin.port}/dns-query/private#ecs=192.0.2.0/24&ecs-override=true`] };
  const checks = [];
  const check = (name, callback) => { callback(); checks.push(name); };
  let child, logs = '';
  const configPath = path.join(directory, 'config.yaml');
  try {
    const config = buildConfig(subscription, mode, options);
    const dnsPort = await freePort(), controlPort = await freePort(), secret = crypto.randomUUID();
    const call = controller(controlPort, secret);
    // Use every checked-in MRS file in the real decoder. Inline personal sets
    // remain as generated, including exact vs suffix domain matching.
    for (const [name, provider] of Object.entries(config['rule-providers'])) {
      if (provider.type === 'inline') continue;
      const file = path.join(directory, name + '.mrs');
      fs.copyFileSync(path.join(projectRoot, 'Rules/generated', provider.behavior, name + '.mrs'), file);
      config['rule-providers'][name] = { type: 'file', behavior: provider.behavior, format: 'mrs', path: file };
    }
    assert(config['rule-providers']['personal-direct']);
    // Intentional overlap tests that an ad block remains ahead of personal DNS.
    const adDomain = '0001-metrics1-drcn-dt-dbankcloud-cn.geac.dbankedge.cn';
    config['rule-providers']['personal-direct'].payload.push(adDomain);
    Object.assign(config, { 'mixed-port': await freePort(), 'allow-lan': false, 'bind-address': '127.0.0.1', 'external-controller': '127.0.0.1:' + controlPort, secret, tun: { enable: false }, ntp: { enable: false }, 'external-ui': '', 'external-ui-url': '', ipv6: false });
    for (const group of config['proxy-groups']) { group.interval = 0; group.lazy = true; }
    for (const provider of Object.values(config['proxy-providers'])) if (provider['health-check']) provider['health-check'].enable = false;

    // Change only resolver destinations to local DoH fixtures; selectors and
    // ECS URL parameters from the production script are kept for wire testing.
    const localResolver = address => {
      if (address.startsWith('rcode://')) return address;
      const split = address.indexOf('#');
      const endpoint = split < 0 ? address : address.slice(0, split);
      const fragment = split < 0 ? '' : address.slice(split);
      if (endpoint.endsWith('/dns-query/private')) return address;
      const name = new URL(endpoint).hostname;
      return `http://127.0.0.1:${fx.origin.port}/dns-query/${encodeURIComponent(name)}` + fragment;
    };
    const mapResolvers = values => Array.isArray(values) ? values.map(localResolver) : localResolver(values);
    for (const key of ['nameserver', 'direct-nameserver', 'proxy-server-nameserver']) config.dns[key] = mapResolvers(config.dns[key]);
    for (const key of ['nameserver-policy', 'proxy-server-nameserver-policy']) {
      if (config.dns[key]) config.dns[key] = Object.fromEntries(Object.entries(config.dns[key]).map(([name, values]) => [name, mapResolvers(values)]));
    }
    Object.assign(config.dns, { listen: '127.0.0.1:' + dnsPort, ipv6: false, 'prefer-h3': false, 'default-nameserver': ['127.0.0.1:' + fx.udpPort], 'use-system-hosts': false });
    fs.writeFileSync(configPath, YAML.stringify(config));
    child = spawn(binary, ['-d', directory, '-f', configPath], { windowsHide: true, env: cleanProxyEnvironment(), stdio: ['ignore', 'pipe', 'pipe'] });
    let launchError;
    child.on('error', error => { launchError = error; });
    for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => { logs = (logs + chunk).slice(-100000); });
    let ready = false;
    for (let attempt = 0; attempt < 70; attempt++) {
      if (launchError) throw launchError;
      if (child.exitCode !== null) throw new Error('Mihomo exited: ' + logs.slice(-3000));
      try { await call('/version'); ready = true; break; } catch { await delay(100); }
    }
    assert(ready, 'Isolated controller must become ready');
    const expectedProviders = Object.keys(config['rule-providers']);
    let providers;
    for (let attempt = 0; attempt < 60; attempt++) {
      providers = (await call('/providers/rules')).providers;
      if (expectedProviders.every(name => providers[name]?.ruleCount > 0)) break;
      await delay(100);
    }
    check('All generated and inline rule sets decode', () => assert(expectedProviders.every(name => providers[name]?.ruleCount > 0)));
    for (const [group, name] of Object.entries({ '代理连接': 'HK 01', '代理DNS': '代理连接', '国外AI': 'US 01' })) await call('/proxies/' + encodeURIComponent(group), 'PUT', { name });
    const dlsiteGroup = await call('/proxies/' + encodeURIComponent('DLsite'));
    check('DLsite retains the Japan default group', () => assert.equal(dlsiteGroup.now, '日本'));
    const ehentaiGroup = await call('/proxies/' + encodeURIComponent('EHentai'));
    check('EHentai retains the US default group', () => assert.equal(ehentaiGroup.now, '美国'));
    for (const [group, name] of Object.entries({ YouTube: '日本', PikPak: '美国', ...(optionalApps ? { Apple: '日本', Meta: '美国', Line: '日本' } : {}) })) await call('/proxies/' + encodeURIComponent(group), 'PUT', { name });

    const fakeCases = [
      ['learn.microsoft.com', false, 'Microsoft exact direct rule'],
      ['child.learn.microsoft.com', true, 'Microsoft child domain stays outside exact rule'],
      ['www.nature.com', false, 'Academic suffix direct rule'],
      ['api.lsposed.org', false, 'Personal suffix direct rule'],
      ['baidu.com', false, 'Upstream domestic real-IP rule'],
      ['cdn.steamcontent.com', true, 'Selectable downloads retain Fake-IP'],
      ['international-gfe.download.nvidia.com', true, 'Download group takes priority over overlapping exact direct rule'],
      ['chatgpt.com', true, 'AI retains Fake-IP'],
      ['www.dlsite.com', true, 'DLsite retains Fake-IP'],
      ['mypikpak.com', true, 'PikPak retains Fake-IP'],
      ['mtalk.google.com', false, 'FCM retains real-IP for push connections'],
      ['youtube.com', true, 'YouTube keeps Fake-IP after application splitting'],
      ['exhentai.org', true, 'Restored EHentai keeps Fake-IP'],
      ['apple.com', true, 'Apple keeps Fake-IP with its application selector enabled or disabled'],
      ['facebook.com', true, 'Meta keeps Fake-IP with its application selector enabled or disabled'],
      ['line.me', true, 'Line keeps Fake-IP with its application selector enabled or disabled'],
      ['netflix.com', true, 'Netflix keeps Fake-IP under overseas media'],
      [adDomain, true, 'Ads stay before the deliberately overlapping direct entry'],
    ];
    for (const [name, expectedFake, label] of fakeCases) {
      const answer = await queryUdp(dnsPort, name);
      check(label, () => {
        assert.equal(answer.rcode, 0, name);
        assert(answer.addresses.length, name + ' must have A answer');
        const actualFake = answer.addresses.every(address => /^198\.(18|19)\./.test(address));
        assert.equal(actualFake, expectedFake, name + ': ' + answer.addresses.join(','));
        if (!expectedFake) assert.deepEqual(answer.addresses, ['203.0.113.7']);
      });
    }

    // The controller is used only for the independent real-resolver path test.
    // Fake-IP assertions above all came from the UDP DNS listener.
    async function realQuery(name, expectedRoute, expectedResolver) {
      await call('/cache/dns/flush', 'POST');
      const start = fx.seen.length;
      const response = await call('/dns/query?name=' + encodeURIComponent(name) + '&type=A');
      await delay(30);
      const records = fx.seen.slice(start).filter(record => record.kind === 'dns' && record.name === name);
      assert(records.length, name + ' must reach a fixture resolver');
      assert(records.every(record => record.route === expectedRoute), name + ' route: ' + JSON.stringify(records));
      assert(records.every(record => expectedResolver.includes(record.resolver)), name + ' resolver: ' + JSON.stringify(records));
      assert(response.Answer?.some(answer => answer.type === 1 && answer.data === '203.0.113.7'), name + ' must return fixture A record');
      checks.push('Real DNS path: ' + name + ' -> ' + expectedRoute);
      return records;
    }
    const domestic = ['dns.alidns.com', 'doh.pub'];
    const foreign = ['dns.google', 'dns.quad9.net'];
    await realQuery('learn.microsoft.com', 'DIRECT', domestic);
    await realQuery('www.nature.com', 'DIRECT', domestic);
    await realQuery('cdn.steamcontent.com', 'DIRECT', domestic);
    await call('/proxies/' + encodeURIComponent('下载更新'), 'PUT', { name: '代理连接' });
    // Selecting a group does not terminate existing DoH keep-alive sessions.
    // Close only local fixture sockets so this checks the next DNS connection.
    fx.origin.closeConnections();
    await delay(30);
    await realQuery('cdn.steamcontent.com', 'HK 01', domestic);
    await realQuery('international-gfe.download.nvidia.com', 'HK 01', domestic);
    await realQuery('chatgpt.com', 'US 01', foreign);
    await realQuery('www.dlsite.com', 'JP 01', foreign);
    await realQuery('child.learn.microsoft.com', 'HK 01', foreign);
    await realQuery('hanime1.me', 'US 01', foreign);
    await realQuery('iwara.tv', 'US 01', foreign);
    await realQuery('www.youtube.com', 'JP 01', foreign);
    await realQuery('mypikpak.com', 'US 01', foreign);
    await realQuery('mtalk.google.com', 'DIRECT', domestic);
    await realQuery('exhentai.org', 'US 01', foreign);
    await realQuery('apple.com', optionalApps ? 'JP 01' : 'HK 01', foreign);
    await realQuery('facebook.com', optionalApps ? 'US 01' : 'HK 01', foreign);
    await realQuery('line.me', optionalApps ? 'JP 01' : 'HK 01', foreign);
    await realQuery('netflix.com', 'HK 01', foreign);
    await call('/proxies/' + encodeURIComponent('FCM'), 'PUT', { name: '代理连接' });
    await call('/proxies/' + encodeURIComponent('EHentai'), 'PUT', { name: '日本' });
    fx.origin.closeConnections();
    await delay(30);
    await realQuery('mtalk.google.com', 'HK 01', domestic);
    await realQuery('exhentai.org', 'JP 01', foreign);

    const beforeAd = fx.seen.length;
    const adAnswer = await call('/dns/query?name=' + encodeURIComponent(adDomain) + '&type=A');
    check('Ads still produce NXDOMAIN without contacting direct DNS', () => {
      assert.equal(adAnswer.Status, 3);
      assert(!fx.seen.slice(beforeAd).some(record => record.kind === 'dns' && record.name === adDomain));
    });
    const publicRecords = fx.seen.filter(record => record.kind === 'dns' && [...domestic, ...foreign].includes(record.resolver));
    if (mode === 'resolver-default') {
      check('Default public DNS sends no forced ECS on the wire', () => assert(publicRecords.length && publicRecords.every(record => record.ecs.length === 0)));
    } else {
      for (const [resolver, subnet] of [['dns.google', '8.8.8.0'], ['dns.quad9.net', '9.9.9.0']]) {
        const records = publicRecords.filter(record => record.resolver === resolver);
        check('Upstream ECS on wire: ' + resolver, () => {
          assert(records.length, resolver + ' must be exercised');
          assert(records.every(record => record.ecs.some(ecs => ecs.family === 1 && ecs.prefix === 24 && ecs.address === subnet)), JSON.stringify(records));
        });
      }
    }
    const privateRecords = fx.seen.filter(record => record.kind === 'dns' && record.name === nodeDomain && record.resolver === 'private');
    check('Private node DNS stays direct and preserves its own ECS on the wire', () => {
      assert(privateRecords.length, 'Private node must actually resolve before proxy connect');
      assert(privateRecords.every(record => record.route === 'DIRECT' && record.ecs.some(ecs => ecs.family === 1 && ecs.prefix === 24 && ecs.address === '192.0.2.0')));
    });
    return { mode, options, passed: true, checks };
  } catch (error) {
    error.message += '\nDNS core log: ' + logs.slice(-3500);
    throw error;
  } finally {
    if (child && child.exitCode === null) { child.kill(); await Promise.race([once(child, 'exit'), delay(3000)]); }
    await fx.close();
    fs.writeFileSync(path.join(directory, 'core.log'), logs);
    if (fs.existsSync(configPath)) fs.unlinkSync(configPath);
  }
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length !== 2 || args[0] !== '--mihomo') throw new Error('Usage: --mihomo <official Mihomo executable>');
  const binary = path.resolve(args[1]);
  const directory = path.join(projectRoot, '.test-runtime', 'dns-behavior-' + crypto.randomUUID());
  fs.mkdirSync(directory, { recursive: true });
  const results = [];
  try {
    for (const mode of ['resolver-default', 'upstream']) results.push(await runCase(binary, mode, directory));
    results.push(await runCase(binary, 'resolver-default', directory, { Apple: true, Meta: true, Line: true }));
    const passed = results.every(result => result.passed);
    const checks = results.reduce((sum, result) => sum + result.checks.length, 0);
    console.log(JSON.stringify({ passed, checks, results }, null, 2));
  } finally {
    fs.writeFileSync(path.join(directory, 'results.json'), JSON.stringify({ passed: results.length === 3 && results.every(result => result.passed), results }, null, 2));
  }
}
main().catch(error => { console.error(error.stack || error.message); process.exitCode = 1; });
