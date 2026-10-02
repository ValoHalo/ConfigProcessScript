#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const YAML = require('yaml');
const { loadScript } = require('./lib/loader');
const { fixtures, freePort } = require('./lib/network-fixtures');
const { cleanProxyEnvironment } = require('./lib/bettbox-core');

const root = path.resolve(__dirname, '..');
const clone = value => JSON.parse(JSON.stringify(value));
const sorted = values => [...values].sort();
const regex = source => new RegExp(source.replace(/^\(\?i\)/, ''), source.startsWith('(?i)') ? 'i' : '');
const node = name => ({ name, type: 'http', server: '127.0.0.1', port: 9 });
const subscription = names => ({ proxies: names.map(node) });
const generate = (names, options = {}) => {
  const api = loadScript('Script/mihomoScript.js');
  Object.assign(api.ruleOptionsEnable, options);
  return clone(api.main(subscription(names)));
};
const groups = cfg => cfg['proxy-groups'];
const byName = (cfg, name) => groups(cfg).find(group => group.name === name);
let count = 0;
const failures = [];
function test(name, check) {
  try { check(); count++; console.log('PASS ' + name); }
  catch (error) { failures.push(name); console.error('FAIL ' + name + '\n' + error.stack); }
}
function nodeNames(cfg) {
  const provider = cfg['proxy-providers']['节点'];
  const excluded = provider['exclude-filter'] && regex(provider['exclude-filter']);
  return provider.payload.filter(proxy => !excluded || !excluded.test(proxy.name)).map(proxy => proxy.name);
}
function candidates(cfg, group) {
  return nodeNames(cfg).filter(name => !group.filter || regex(group.filter).test(name));
}
function buckets(cfg) {
  return groups(cfg).filter(group => group.type === 'select' && group.use?.includes('节点') && group.proxies?.length === 2 && byName(cfg, group.proxies[0])?.type === 'url-test' && byName(cfg, group.proxies[1])?.type === 'load-balance');
}
function expectBucket(cfg, label, expected) {
  const group = byName(cfg, label);
  assert(group, label + ': missing group');
  checkBucket(cfg, group, expected);
  return group;
}
function checkBucket(cfg, group, expected) {
  assert(buckets(cfg).includes(group), group.name + ': must select two automatic children');
  assert.deepEqual(group.use, ['节点']);
  assert.deepEqual(sorted(candidates(cfg, group)), sorted(expected), group.name + ': incorrect provider candidates');
  for (const [index, type] of ['url-test', 'load-balance'].entries()) {
    const child = byName(cfg, group.proxies[index]);
    assert.equal(child.type, type);
    assert.deepEqual(child.use, ['节点']);
    assert.deepEqual(sorted(candidates(cfg, child)), sorted(expected), child.name + ': incorrect provider candidates');
    assert.equal(child['include-all-providers'], undefined);
    assert.equal(child['include-all'], undefined);
    assert.equal(child.hidden, true, child.name + ': automatic modes belong inside the parent');
    if (type === 'load-balance') assert.equal(child.strategy, 'round-robin');
  }
  assert(expected.length > 0, 'An empty bucket must never be generated');
}
function checkReferences(cfg) {
  const names = groups(cfg).map(group => group.name);
  assert.equal(new Set(names).size, names.length, 'Group names must be unique');
  const allowed = new Set([...names, ...(cfg.proxies || []).map(proxy => proxy.name), 'DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'PASS-RULE']);
  for (const group of groups(cfg)) {
    for (const target of group.proxies || []) assert(allowed.has(target), group.name + ': unknown static target ' + target);
    for (const provider of group.use || []) assert(cfg['proxy-providers'][provider], group.name + ': unknown provider ' + provider);
  }
  for (const rules of [cfg.rules, ...Object.values(cfg['sub-rules'] || {})]) {
    for (const rule of rules) {
      const parts = rule.split(',');
      if (parts.at(-1) === 'no-resolve') parts.pop();
      const target = parts.at(-1);
      if (parts[0] === 'SUB-RULE') assert(cfg['sub-rules'][target], 'Unknown sub-rule ' + target);
      else assert(allowed.has(target), 'Unknown rule target ' + target);
    }
  }
  for (const provider of Object.values(cfg['rule-providers'])) if (provider.proxy) assert(allowed.has(provider.proxy), 'Unknown rule download proxy ' + provider.proxy);
  assert(!groups(cfg).some(group => /\|(?:故障转移|轮询下载)$/.test(group.name)), 'Old regional groups must be removed');
  for (const group of groups(cfg)) assert(!(group.proxies || []).some(name => /\|(?:故障转移|轮询下载)$/.test(name)), 'Old regional reference in ' + group.name);
  for (const service of ['代理连接', '直接连接', '代理DNS', '代理QUIC', 'TELEGRAM', '国外AI', '下载相关', '风控安全', 'GOOGLE', '海外媒体', 'GLOBAL']) assert(byName(cfg, service), 'Missing service ' + service);
  assert.equal(byName(cfg, '最低延迟').type, 'url-test');
  assert.equal(byName(cfg, '故障转移').type, 'fallback');
}

function configurationTests() {
  test('Only regions with actual eligible nodes are generated', () => {
    const cfg = generate(['HK 01']);
    expectBucket(cfg, '香港', ['HK 01']);
    assert.deepEqual(buckets(cfg).map(group => group.name), ['香港']);
    checkReferences(cfg);
  });
  test('Excluded Dutch informational entries do not create a Netherlands group', () => {
    const cfg = generate(['HK 01', 'NL 剩余流量', '荷兰 官网']);
    assert.deepEqual(buckets(cfg).map(group => group.name), ['香港']);
    checkReferences(cfg);
  });
  test('A genuine Dutch node creates the Netherlands group', () => {
    const cfg = generate(['HK 01', '🇳🇱 NL 01']);
    expectBucket(cfg, '荷兰', ['🇳🇱 NL 01']);
    checkReferences(cfg);
  });
  test('All eight supported regions and unmatched nodes remain selectable', () => {
    const names = ['🇭🇰 Hong Kong 01', '🇹🇼 Taiwan 01', '🇸🇬 Singapore 01', '🇯🇵 Japan 01', '🇺🇸 United States 01', '🇩🇪 Germany 01', '🇬🇧 United Kingdom 01', '🇳🇱 Netherlands 01', 'Canada 01'];
    const cfg = generate(names);
    ['香港', '台湾', '新加坡', '日本', '美国', '德国', '英国', '荷兰', '其他节点'].forEach((region, index) => expectBucket(cfg, region, [names[index]]));
    assert.equal(buckets(cfg).length, 9);
    checkReferences(cfg);
  });
  test('Rate groups are omitted when the subscription has no matching rates', () => {
    const cfg = generate(['HK 01', 'JP 1x', 'US 1.99x']);
    assert(!byName(cfg, '低倍率节点'));
    assert(!byName(cfg, '高倍率节点'));
  });
  test('Rate boundaries use numeric values without decimal substring mistakes', () => {
    const low = ['HK 0.5x', 'HK x0.3', 'HK 0.3倍率'];
    const high = ['US 2x', 'US 10.5x'];
    const neither = ['JP 0.59x', 'JP 1.99x', 'JP 低倍0.59', 'JP 1x'];
    const cfg = generate([...low, ...high, ...neither]);
    expectBucket(cfg, '低倍率节点', low);
    expectBucket(cfg, '高倍率节点', high);
    expectBucket(cfg, '香港', low);
    expectBucket(cfg, '美国', high);
    expectBucket(cfg, '日本', neither);
    checkReferences(cfg);
  });
  test('Exact name filters preserve regular expression metacharacters', () => {
    const names = ['HK [a]+(b).$^?{2}|\\ 0.5x', 'JP [one]+ 2x', 'US (two)? 1x', 'Unknown [a]+'];
    const cfg = generate(names);
    expectBucket(cfg, '香港', [names[0]]);
    expectBucket(cfg, '低倍率节点', [names[0]]);
    expectBucket(cfg, '高倍率节点', [names[1]]);
    for (const group of buckets(cfg)) {
      for (const name of candidates(cfg, group)) {
        assert(!regex(group.filter).test('x' + name), group.name + ': prefix must not match');
        assert(!regex(group.filter).test(name + ' suffix'), group.name + ': suffix must not match');
      }
    }
    checkReferences(cfg);
  });
  test('Repeated main calls do not retain previously discovered groups', () => {
    const api = loadScript('Script/mihomoScript.js');
    const source = subscription(['NL 01', 'JP 0.5x']);
    const original = clone(source);
    const first = clone(api.main(source));
    assert(byName(first, '荷兰'));
    const second = clone(api.main(subscription(['HK 01'])));
    assert.deepEqual(buckets(second).map(group => group.name), ['香港']);
    assert.deepEqual(source, original, 'Input subscription must remain unchanged');
    assert.deepEqual(clone(api.main(source)), first, 'Repeating the original input must be deterministic');
  });
  test('Dynamic names avoid collisions with actual subscription node names', () => {
    const names = ['日本', '日本|最低延迟', '日本|负载均衡', '日本（分组）', 'US 2x'];
    const cfg = generate(names);
    for (const group of groups(cfg)) assert(!names.includes(group.name), 'Group collides with node: ' + group.name);
    const regional = buckets(cfg).find(group => candidates(cfg, group).includes('日本'));
    assert(regional, 'Japanese parent missing after collision resolution');
    checkBucket(cfg, regional, names.slice(0, 4));
    assert.equal(byName(cfg, 'DLsite').proxies[0], regional.name);
    checkReferences(cfg);
  });
  test('AI selector retains only concrete American and Japanese nodes plus REJECT', () => {
    const cfg = generate(['US 01', 'JP 02', 'HK 03', 'NL 04', 'US 剩余流量']);
    const ai = byName(cfg, '国外AI');
    assert.equal(ai.type, 'select');
    assert.deepEqual(ai.proxies, ['REJECT']);
    assert.deepEqual(ai.use, ['节点']);
    assert.deepEqual(sorted(candidates(cfg, ai)), ['JP 02', 'US 01']);
    assert.equal(ai['default-selected'], 'REJECT');
    assert.equal(ai['include-all-providers'], undefined);
    assert.equal(ai['include-all'], undefined);
  });
  test('AI works safely when no American or Japanese nodes are available', () => {
    const cfg = generate(['HK 01']);
    const ai = byName(cfg, '国外AI');
    assert.deepEqual(ai.proxies, ['REJECT']);
    assert.deepEqual(candidates(cfg, ai), []);
    checkReferences(cfg);
  });
  test('DLsite defaults to the ordinary Japanese selector', () => {
    const cfg = generate(['JP 01', 'US 01']);
    const dlsite = byName(cfg, 'DLsite');
    assert.equal(dlsite.type, 'select');
    assert.equal(dlsite.proxies[0], '日本');
    assert.equal(dlsite['default-selected'], '日本');
    assert(dlsite.proxies.includes('代理连接'));
    assert.equal(byName(cfg, dlsite.proxies[0]).type, 'select');
  });
  test('Without Japan, DLsite starts at REJECT and still allows manual selection', () => {
    const cfg = generate(['HK 01']);
    const dlsite = byName(cfg, 'DLsite');
    assert.equal(dlsite.type, 'select');
    assert.equal(dlsite.proxies[0], 'REJECT');
    assert.equal(dlsite['default-selected'], 'REJECT');
    assert(dlsite.proxies.includes('香港'));
    assert(dlsite.proxies.includes('代理连接'));
    checkReferences(cfg);
  });
  test('Visible menus place switches and applications before regions and multiplier groups', () => {
    const cfg = generate(['HK 0.5x', 'JP 01', 'US 2x', 'Canada 01']);
    const visible = groups(cfg).filter(group => !group.hidden).map(group => group.name);
    assert.deepEqual(visible.slice(0, 4), ['代理连接', '直接连接', '代理DNS', '代理QUIC']);
    const applications = ['国外AI', 'OneDrive', 'DLsite', 'FCM', 'YouTube', '海外媒体', 'Microsoft', 'Steam', 'Twitter', 'PikPak', 'EHentai', 'TELEGRAM', '下载更新', '下载相关', '风控安全', 'GOOGLE'];
    assert.equal(visible[visible.indexOf('YouTube') + 1], '海外媒体');
    for (const name of ['Apple', 'Meta', 'Line', 'Netflix']) assert(!visible.includes(name));
    const regions = ['香港', '日本', '美国', '其他节点'];
    const firstRegion = Math.min(...regions.map(name => visible.indexOf(name)));
    for (const name of applications) assert(visible.indexOf(name) >= 4 && visible.indexOf(name) < firstRegion, name + ': application must precede regions');
    for (const name of regions) assert(visible.indexOf(name) > 3 && visible.indexOf(name) < visible.indexOf('低倍率节点'), name + ': region must precede multiplier groups');
    assert.deepEqual(visible.slice(-2), ['低倍率节点', '高倍率节点']);
    assert.equal(byName(cfg, '最低延迟').hidden, true);
    assert.equal(byName(cfg, '故障转移').hidden, true);
    assert.equal(byName(cfg, 'GLOBAL').hidden, true);
    checkReferences(cfg);
  });
  test('Restored applications expose direct and regional choices with their intended defaults', () => {
    const cfg = generate(['HK 01', 'JP 01', 'US 01'], { Apple: true, Meta: true, Line: true });
    for (const name of ['FCM', 'YouTube', 'Microsoft', 'Apple', 'Steam', 'Twitter', 'Meta', 'Line', 'PikPak', 'EHentai']) {
      const group = byName(cfg, name);
      assert(group, name + ': missing application selector');
      assert.equal(group.type, 'select');
      for (const choice of ['直接连接', '代理连接', '香港', '日本', '美国']) assert(group.proxies.includes(choice), name + ': missing manual choice ' + choice);
      const expected = name === 'FCM' ? '直接连接' : name === 'EHentai' ? '美国' : '代理连接';
      assert.equal(group.proxies[0], expected, name + ': initial choice');
    }
  });
  test('EHentai falls back to the proxy selector when American nodes are absent', () => {
    const cfg = generate(['HK 01', 'JP 01']);
    const group = byName(cfg, 'EHentai');
    assert.equal(group.proxies[0], '代理连接');
    assert(!group.proxies.includes('美国'));
    assert(group.proxies.includes('日本'));
    checkReferences(cfg);
  });
  test('Application switches remove optional rules, providers and DNS references', () => {
    const definitions = JSON.parse(fs.readFileSync(path.join(root, 'config/app-groups.json'), 'utf8'));
    const allEnabled = Object.fromEntries(definitions.map(app => [app.name, true]));
    const baseline = generate(['HK 01', 'JP 01', 'US 01'], allEnabled);
    for (const app of definitions.filter(app => !app.existingGroup)) {
      assert(byName(baseline, app.name), app.name + ': enabled baseline is required');
      const cfg = generate(['HK 01', 'JP 01', 'US 01'], { ...allEnabled, [app.name]: false });
      if (!app.existingGroup) assert(!byName(cfg, app.name), app.name + ': disabled group remains');
      assert.equal(cfg['rule-providers'][app.domain], undefined, app.name + ': disabled domain provider remains');
      assert(!cfg.rules.some(rule => rule.includes('RULE-SET,' + app.domain + ')') || rule.includes('sub-app-' + app.domain)), app.name + ': disabled rule remains');
      assert.equal(cfg['sub-rules']['sub-app-' + app.domain], undefined, app.name + ': disabled sub-rule remains');
      assert(!Object.keys(cfg.dns['nameserver-policy']).some(key => key.startsWith('rule-set:') && key.slice(9).split(',').includes(app.domain)), app.name + ': disabled DNS policy remains');
      assert(!cfg.dns['fake-ip-filter'].some(rule => rule.startsWith('RULE-SET,' + app.domain + ',')), app.name + ': disabled fake-IP rule remains');
      if (app.ip && !app.baseIp) assert.equal(cfg['rule-providers'][app.ip], undefined, app.name + ': disabled IP provider remains');
      checkReferences(cfg);
    }
    const fcmOff = generate(['HK 01'], { FCM: false });
    assert(fcmOff.rules.includes('DST-PORT,5228-5230,直接连接'));
    assert(generate(['HK 01'], { Twitter: false }).rules.includes('SUB-RULE,(RULE-SET,safe_ip),sub-safe'));
    assert(generate(['HK 01']).rules.includes('SUB-RULE,(RULE-SET,media_ip),sub-media'));
  });
  test('Application DNS follows the application while retaining personal and AI precedence', () => {
    const cfg = generate(['HK 01', 'JP 01', 'US 01'], { Apple: true, Meta: true, Line: true });
    const definitions = JSON.parse(fs.readFileSync(path.join(root, 'config/app-groups.json'), 'utf8'));
    const policies = cfg.dns['nameserver-policy'];
    const keys = Object.keys(policies);
    const filters = cfg.dns['fake-ip-filter'];
    for (const app of definitions) {
      const key = 'rule-set:' + app.domain;
      assert(policies[key]?.every(address => address.includes('#' + app.name)), app.name + ': DNS does not follow application');
      assert(keys.indexOf('rule-set:personal-direct') < keys.indexOf(key), app.name + ': personal DNS priority');
      assert(keys.indexOf(key) < keys.findIndex(value => value.includes('proxy-lite')), app.name + ': aggregate DNS priority');
      const filter = 'RULE-SET,' + app.domain + ',' + (app.name === 'FCM' ? 'real-ip' : 'fake-ip');
      assert(filters.includes(filter), app.name + ': missing fake-IP decision');
      assert(filters.indexOf('RULE-SET,personal-direct,real-ip') < filters.indexOf(filter), app.name + ': personal fake-IP priority');
      assert(keys.indexOf('rule-set:ai') < keys.indexOf(key), app.name + ': AI DNS priority');
      assert(filters.indexOf('RULE-SET,ai,fake-ip') < filters.indexOf(filter), app.name + ': AI fake-IP priority');
      assert(keys.indexOf(key) < keys.indexOf('rule-set:proxy@direct'), app.name + ': direct exception DNS priority');
      assert(filters.indexOf(filter) < filters.indexOf('RULE-SET,proxy@direct,real-ip'), app.name + ': direct exception Fake-IP priority');
    }
  });
  test('Google and overseas media DNS follow their selectors after more specific applications', () => {
    const cfg = generate(['HK 01', 'JP 01', 'US 01']);
    const policies = cfg.dns['nameserver-policy'];
    const keys = Object.keys(policies);
    const filters = cfg.dns['fake-ip-filter'];
    for (const [id, group] of [['google', 'GOOGLE'], ['media', '海外媒体']]) {
      assert(policies['rule-set:' + id].every(address => address.includes('#' + group)));
      assert(!keys.some(key => key !== 'rule-set:' + id && key.startsWith('rule-set:') && key.slice(9).split(',').includes(id)));
    }
    assert(keys.indexOf('rule-set:youtube') < keys.indexOf('rule-set:google'));
    assert(keys.indexOf('rule-set:google') < keys.indexOf('rule-set:proxy@direct'));
    assert(keys.indexOf('rule-set:steam') < keys.indexOf('rule-set:microsoft'));
    assert(filters.indexOf('RULE-SET,youtube,fake-ip') < filters.indexOf('RULE-SET,google,fake-ip'));
    assert(filters.indexOf('RULE-SET,google,fake-ip') < filters.indexOf('RULE-SET,proxy@direct,real-ip'));
    assert(filters.indexOf('RULE-SET,steam,fake-ip') < filters.indexOf('RULE-SET,microsoft,fake-ip'));
  });
  test('Disabling service DNS keeps application routing and Fake-IP without binding application resolvers', () => {
    const names = ['HK 01', 'JP 01', 'US 01'];
    const enabled = generate(names, { Apple: true, Meta: true, Line: true });
    const disabled = generate(names, { Apple: true, Meta: true, Line: true, DNS跟随服务: false });
    const definitions = JSON.parse(fs.readFileSync(path.join(root, 'config/app-groups.json'), 'utf8'));
    assert.deepEqual(disabled.rules, enabled.rules, 'DNS switch must not change application routing');
    assert.deepEqual(disabled.dns['fake-ip-filter'], enabled.dns['fake-ip-filter'], 'DNS switch must preserve application Fake-IP classification');
    for (const app of definitions) {
      assert.equal(disabled.dns['nameserver-policy']['rule-set:' + app.domain], undefined, app.name + ': DNS binding remains disabled');
    }
    checkReferences(disabled);
  });
}

async function coreTest(binary, label, names) {
  const directory = path.join(root, '.test-runtime', 'groups-' + crypto.randomUUID());
  fs.mkdirSync(directory, { recursive: true });
  const fx = await fixtures();
  const cfg = generate(names);
  const expected = buckets(cfg).map(group => ({ parent: group.name, children: group.proxies, nodes: candidates(cfg, group) }));
  const aiCandidates = candidates(cfg, byName(cfg, '国外AI'));
  let child, logs = '';
  try {
    const controller = await freePort(), secret = crypto.randomUUID();
    Object.assign(cfg, { 'mixed-port': await freePort(), 'allow-lan': false, 'bind-address': '127.0.0.1', 'external-controller': '127.0.0.1:' + controller, secret, tun: { enable: false }, ntp: { enable: false }, 'external-ui': '', 'external-ui-url': '', ipv6: false, dns: { enable: false }, sniffer: { enable: false }, 'find-process-mode': 'off' });
    // All optional startup checks and data providers stay on loopback or inline.
    for (const provider of Object.values(cfg['proxy-providers'])) {
      assert.equal(provider.type, 'inline');
      provider.payload = provider.payload.map((proxy, index) => ({ ...proxy, type: 'http', server: '127.0.0.1', port: fx.proxies[index % fx.proxies.length].port }));
      provider['health-check'] = { enable: false, interval: 0, lazy: true, url: 'http://127.0.0.1:' + fx.origin.port + '/health' };
    }
    for (const [name, provider] of Object.entries(cfg['rule-providers'])) cfg['rule-providers'][name] = { type: 'inline', behavior: provider.behavior, payload: provider.behavior === 'ipcidr' ? ['192.0.2.0/24'] : provider.behavior === 'classical' ? ['DOMAIN,fixture.invalid'] : ['fixture.invalid'] };
    for (const group of groups(cfg)) Object.assign(group, { interval: 0, lazy: true, url: 'http://127.0.0.1:' + fx.origin.port + '/health' });
    fs.writeFileSync(path.join(directory, 'config.yaml'), YAML.stringify(cfg));
    const control = route => new Promise((resolve, reject) => {
      const request = http.get({ hostname: '127.0.0.1', port: controller, path: route, headers: { Authorization: 'Bearer ' + secret }, agent: false }, response => {
        const chunks = [];
        response.on('data', chunk => chunks.push(chunk));
        response.on('end', () => {
          if (response.statusCode !== 200) return reject(new Error('Controller HTTP ' + response.statusCode));
          try { resolve(JSON.parse(Buffer.concat(chunks).toString())); } catch (error) { reject(error); }
        });
      });
      request.on('error', reject);
      request.setTimeout(1000, () => request.destroy(new Error('Controller timeout')));
    });
    child = spawn(binary, ['-d', directory, '-f', path.join(directory, 'config.yaml')], { windowsHide: true, env: cleanProxyEnvironment(), stdio: ['ignore', 'pipe', 'pipe'] });
    let launchError;
    child.on('error', error => { launchError = error; });
    for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => { logs = (logs + chunk).slice(-50000); });
    let loaded;
    for (let attempt = 0; attempt < 60; attempt++) {
      if (launchError) throw launchError;
      if (child.exitCode !== null) throw new Error('Mihomo exited: ' + logs);
      try {
        loaded = (await control('/proxies')).proxies;
        if (expected.every(item => loaded[item.parent]?.all?.includes(item.nodes[0]))) break;
      } catch {}
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    assert(loaded, 'Mihomo did not become ready: ' + logs);
    for (const item of expected) {
      assert.equal(loaded[item.parent].type, 'Selector', item.parent);
      assert.deepEqual(sorted(loaded[item.parent].all), sorted([...item.children, ...item.nodes]), item.parent + ': core must expose both modes and actual provider nodes');
      for (const [index, type] of ['URLTest', 'LoadBalance'].entries()) {
        assert.equal(loaded[item.children[index]].type, type, item.children[index]);
        assert.deepEqual(sorted(loaded[item.children[index]].all), sorted(item.nodes), item.children[index] + ': core provider candidates');
      }
    }
    assert.deepEqual(sorted(loaded['国外AI'].all), sorted(['REJECT', ...aiCandidates]), 'Core AI choices');
    assert.equal(loaded['国外AI'].now, 'REJECT');
    assert.equal(loaded.DLsite.now, byName(cfg, 'DLsite').proxies[0], 'Core DLsite initial choice');
    assert.equal(loaded.EHentai.now, byName(cfg, 'EHentai').proxies[0], 'Core EHentai initial choice');
    assert.equal(loaded.FCM.now, '直接连接', 'Core FCM initial choice');
    const loadedProviders = (await control('/providers/proxies')).providers;
    const providerNodes = new Set(Object.values(loadedProviders).flatMap(provider => (provider.proxies || []).map(proxy => proxy.name)));
    for (const group of groups(cfg)) {
      assert(loaded[group.name], 'Core missing group ' + group.name);
      for (const target of loaded[group.name].all || []) assert(loaded[target] || providerNodes.has(target), group.name + ': core has dangling target ' + target);
    }
    checkReferences(cfg);
    count++;
    console.log('PASS official Mihomo group candidates: ' + label + ' (' + expected.length + ' buckets)');
  } finally {
    if (child?.pid && child.exitCode === null) { const exited = once(child, 'exit'); child.kill(); await exited; }
    await fx.close();
    fs.writeFileSync(path.join(directory, 'core.log'), logs);
    if (fs.existsSync(path.join(directory, 'config.yaml'))) fs.unlinkSync(path.join(directory, 'config.yaml'));
  }
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length && (args.length !== 2 || args[0] !== '--mihomo')) throw new Error('Usage: node Test/run-group-tests.js [--mihomo <official Mihomo executable>]');
  configurationTests();
  if (failures.length) throw new Error(failures.length + ' configuration behavior checks failed: ' + failures.join('; '));
  if (args.length) {
    const binary = path.resolve(args[1]);
    await coreTest(binary, 'all regions, rates and metacharacters', ['HK [a]+ 0.5x', 'TW 01', 'SG 01', 'JP 0.59x', 'US 2x', 'DE 01', 'UK 01', 'NL 01', 'Canada 01', 'NL 剩余流量']);
    await coreTest(binary, 'only Hong Kong; absent Japan, America and Netherlands', ['HK 01', 'NL 剩余流量']);
    await coreTest(binary, 'node/group name collisions', ['日本', '日本|最低延迟', '日本|负载均衡', '日本（分组）', 'US 2x']);
  }
  console.log(count + ' group behavior checks passed.');
}
main().catch(error => { console.error(error.stack); process.exitCode = 1; });
