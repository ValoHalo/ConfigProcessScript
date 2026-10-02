#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const espree = require('espree');
const { getQuickJS } = require('quickjs-emscripten');
const { generate, build, personalList } = require('../Tools/build-scripts');
const root = path.resolve(__dirname, '..');
const code = fs.readFileSync(path.join(root, 'Script/mihomoScript.js'), 'utf8');
const original = fs.readFileSync(path.join(root, 'vendor/echsfxy/mihomo.js'), 'utf8');
const fixture = () => ({ proxies: ['HK 01', 'US 01', 'JP 01', 'US 02'].map((name, i) => ({ name, type: 'ss', server: 'node' + i + '.example.net', port: 443, cipher: 'aes-128-gcm', password: 'fixture' })) });
const clone = value => JSON.parse(JSON.stringify(value));
function evaluate(source, input, options = {}) {
  const ctx = vm.createContext({ input: clone(input) });
  vm.runInContext(source + '\n' + (source === original ? '' : 'Object.assign(ruleOptionsEnable,' + JSON.stringify(options) + ');') + '\nresult = main(input);', ctx, { timeout: 4000 });
  return clone(ctx.result);
}
let count = 0;
function test(name, check) { check(); count++; console.log('PASS ' + name); }

async function main() {
  const input = fixture(), upstream = evaluate(original, input), current = evaluate(code, input);
  test('Generated full script is current and standalone ES2020', () => { assert.equal(generate(), code); build({ check: true }); espree.parse(code, { ecmaVersion: 2020, sourceType: 'script' }); });
  test('Unchanged Echsfxy groups and generic settings follow upstream', () => {
    for (const group of upstream['proxy-groups']) if (!['国外AI', 'GLOBAL'].includes(group.name)) assert.deepEqual(current['proxy-groups'].find(g => g.name === group.name), group);
    for (const key of ['sub-rules', 'proxies', 'sniffer', 'profile', 'experimental', 'ipv6', 'tcp-concurrent', 'unified-delay', 'keep-alive-interval']) assert.deepEqual(current[key], upstream[key]);
    assert.deepEqual(current['proxy-providers'], upstream['proxy-providers']);
  });
  test('Upstream routing order is preserved around personal additions', () => {
    assert.deepEqual(current.rules.filter(rule => upstream.rules.includes(rule)), upstream.rules);
    assert(current.rules.indexOf('RULE-SET,ads,REJECT') < current.rules.indexOf('PROCESS-NAME,OneDrive.exe,OneDrive'));
    assert(current.rules.indexOf('PROCESS-NAME,OneDrive.exe,OneDrive') < current.rules.indexOf('DOMAIN,api.onedrive.com,直接连接'));
    assert(current.rules.indexOf('DOMAIN,login.microsoftonline.com,直接连接') < current.rules.indexOf('RULE-SET,proxy@direct,直接连接'));
  });
  test('Microsoft rules remain exact and academic rules remain suffixes', () => {
    assert(current.rules.includes('DOMAIN,login.microsoftonline.com,直接连接'));
    assert(!current.rules.includes('DOMAIN-SUFFIX,login.microsoftonline.com,直接连接'));
    assert(current.rules.includes('DOMAIN-SUFFIX,arxiv.org,直接连接'));
  });
  test('AI uses concrete allowed nodes and starts at REJECT', () => {
    const group = current['proxy-groups'].find(g => g.name === '国外AI');
    assert.deepEqual(group.proxies, ['REJECT']);
    assert.deepEqual(group.use, ['节点']);
    const allowed = new RegExp(group.filter);
    assert(allowed.test('US 01') && allowed.test('JP 01') && !allowed.test('HK 01') && !allowed.test('xUS 01'));
    assert.equal(group['include-all-providers'], undefined);
    assert.equal(evaluate(code, { proxies: [fixture().proxies[0]] })['proxy-groups'].find(g => g.name === '国外AI').proxies.length, 1);
    assert.equal(current.rules[current.rules.indexOf('SUB-RULE,(RULE-SET,ai),sub-ai') + 1], 'AND,((NETWORK,UDP),(RULE-SET,ai)),REJECT');
  });
  test('DLsite is a normal selector defaulting to Japan', () => {
    const group = current['proxy-groups'].find(g => g.name === 'DLsite');
    assert.equal(group.type, 'select'); assert.equal(group.proxies[0], '日本|故障转移');
    assert.equal(group['include-all-providers'], true); assert(group.proxies.includes('代理连接'));
    assert(!group.proxies.includes('REJECT'));
  });
  test('Download domains use the personal manual direct group', () => {
    assert(current.rules.includes('DOMAIN-SUFFIX,download.windowsupdate.com,下载更新'));
    assert(!current.rules.includes('DOMAIN-SUFFIX,docker.com,下载更新'));
    assert.equal(current['proxy-groups'].find(g => g.name === '下载更新').proxies[0], '直接连接');
  });
  test('OneDrive option controls process routing and process detection', () => {
    assert.equal(current['find-process-mode'], 'strict');
    const off = evaluate(code, input, { OneDrive: false });
    assert.equal(off['find-process-mode'], upstream['find-process-mode']);
    assert(!off.rules.some(rule => rule.startsWith('PROCESS-NAME,')));
  });
  test('Disabling optional services removes their rules, groups and DNS policies', () => {
    const off = evaluate(code, input, { DLsite: false, 大流量下载直连: false, AI固定出口: false });
    assert(!off['proxy-groups'].some(g => ['DLsite', '下载更新'].includes(g.name)));
    assert.equal(off['rule-providers'].dlsite, undefined);
    assert(!Object.keys(off.dns['nameserver-policy']).some(k => k.includes('dlsite')));
    assert.deepEqual(off['proxy-groups'].find(g => g.name === '国外AI'), upstream['proxy-groups'].find(g => g.name === '国外AI'));
  });
  test('DNS preserves upstream resolvers without forcing an unrelated ECS subnet', () => {
    for (const key of ['default-nameserver', 'direct-nameserver', 'prefer-h3', 'enhanced-mode', 'fake-ip-filter-mode']) assert.deepEqual(current.dns[key], upstream.dns[key]);
    assert.deepEqual(current.dns.nameserver, upstream.dns.nameserver.map(address => address.replace(/&ecs=[^&]+/g, '').replace(/&ecs-override=[^&]+/g, '')));
    assert(current.dns['nameserver-policy']['rule-set:ai'].every(s => s.includes('#国外AI')));
    assert(current.dns['nameserver-policy']['rule-set:dlsite'].every(s => s.includes('#DLsite')));
    assert(!Object.keys(current.dns['nameserver-policy']).some(k => k.includes('ai,') || k.includes(',ai')));
    assert(!current.dns['nameserver-policy']['rule-set:ai'].some(s => s.includes('ecs=')));
    assert(!current.dns['nameserver-policy']['rule-set:dlsite'].some(s => s.includes('ecs=')));
    const policyKeys = Object.keys(current.dns['nameserver-policy']);
    assert(policyKeys.indexOf('rule-set:personal-direct') < policyKeys.indexOf('rule-set:dlsite'));
    assert(policyKeys.indexOf('rule-set:dlsite') < policyKeys.findIndex(k => k.includes('proxy-lite')));
  });
  test('Personal DNS uses the same exact and suffix rules and keeps download precedence', () => {
    const direct = current['rule-providers']['personal-direct'].payload;
    assert(direct.includes('login.microsoftonline.com'));
    assert(!direct.includes('+.login.microsoftonline.com'));
    assert(direct.includes('+.arxiv.org'));
    const filters = current.dns['fake-ip-filter'];
    assert(filters.indexOf('RULE-SET,ads,fake-ip') < filters.indexOf('RULE-SET,personal-download,fake-ip'));
    assert(filters.indexOf('RULE-SET,personal-download,fake-ip') < filters.indexOf('RULE-SET,personal-direct,real-ip'));
    assert(current.dns['nameserver-policy']['rule-set:personal-download'].every(s => s.includes('#下载更新')));
    assert.equal(evaluate(code, input, { 大流量下载直连: false })['rule-providers']['personal-download'], undefined);
  });
  test('Subscription node ECS stays intact and the upstream ECS mode is opt-in', () => {
    const custom = fixture();
    custom.dns = { 'proxy-server-nameserver': ['https://private.example.net/dns-query#DIRECT&ecs=192.0.2.0/24&ecs-override=true'] };
    assert(evaluate(code, custom).dns['proxy-server-nameserver'][0].includes('ecs=192.0.2.0/24&ecs-override=true'));
    const legacy = evaluate(code.replace('"ecsMode": "resolver-default"', '"ecsMode": "upstream"'), input);
    assert.deepEqual(legacy.dns.nameserver, upstream.dns.nameserver);
  });
  test('Client controls listener, controller and TUN settings', () => {
    for (const key of ['tun', 'allow-lan', 'mixed-port', 'external-controller', 'secret']) assert.equal(current[key], undefined);
    assert.deepEqual(input, fixture());
  });
  test('Personal lists cannot silently widen exact matches or inject targets', () => {
    assert.deepEqual(personalList('DOMAIN,example.com', 'test', ['DOMAIN']), ['DOMAIN,example.com']);
    assert.throws(() => personalList('DOMAIN-SUFFIX,example.com', 'test', ['DOMAIN']));
    assert.throws(() => personalList('DOMAIN,example.com,DIRECT', 'test', ['DOMAIN']));
  });
  const dir = fs.mkdtempSync(path.join(root, '.test-runtime/build-'));
  for (const file of ['src', 'config', 'vendor', 'Rules/personal']) fs.cpSync(path.join(root, file), path.join(dir, file), { recursive: true });
  test('Publication uses this repository and leaves upstream snapshot unchanged', () => {
    fs.writeFileSync(path.join(dir, 'config/project.json'), JSON.stringify({ repository: 'example/config', branch: 'main' }));
    const published = evaluate(generate(dir), input);
    for (const provider of Object.values(published['rule-providers'])) if (provider.type === 'http') assert(provider.url.startsWith('https://raw.githubusercontent.com/example/config/main/Rules/generated/'));
    assert.equal(fs.readFileSync(path.join(dir, 'vendor/echsfxy/mihomo.js'), 'utf8'), original);
  });
  test('Unexpected upstream change prevents generating a release', () => {
    fs.appendFileSync(path.join(dir, 'vendor/echsfxy/mihomo.js'), '\n// changed');
    assert.throws(() => generate(dir), /hash differs/);
  });
  const QuickJS = await getQuickJS();
  for (const options of [{}, { OneDrive: false }, { DLsite: false }, { AI固定出口: false }, { 大流量下载直连: false }, { DNS跟随服务: false }]) {
    const ctx = QuickJS.newContext();
    try {
      const result = ctx.evalCode(code + '\nObject.assign(ruleOptionsEnable,' + JSON.stringify(options) + ');\nJSON.stringify(main(' + JSON.stringify(input) + '));');
      if (result.error) { const error = ctx.dump(result.error); result.error.dispose(); throw new Error(JSON.stringify(error)); }
      const output = JSON.parse(ctx.dump(result.value)); result.value.dispose();
      assert.deepEqual(output, evaluate(code, input, options)); count++;
    } finally { ctx.dispose(); }
  }
  console.log('Script/build checks: ' + count + ' passed (including 6 Node/QuickJS comparisons).');
}
fs.mkdirSync(path.join(root, '.test-runtime'), { recursive: true });
main().catch(error => { console.error(error.stack); process.exitCode = 1; });
