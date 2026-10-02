#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const espree = require('espree');
const { getQuickJS } = require('quickjs-emscripten');
const { generate, build, personalList, validateProviderReferences } = require('../Tools/build-scripts');
const root = path.resolve(__dirname, '..');
const code = fs.readFileSync(path.join(root, 'Script/mihomoScript.js'), 'utf8');
const fixture = () => ({ proxies: ['HK 01', 'US 01', 'JP 01', 'US 02'].map((name, i) => ({ name, type: 'ss', server: 'node' + i + '.example.net', port: 443, cipher: 'aes-128-gcm', password: 'fixture' })) });
const clone = value => JSON.parse(JSON.stringify(value));
function evaluate(source, input, options = {}, entry = 'main') {
  const ctx = vm.createContext({ input: clone(input) });
  vm.runInContext(source + '\nObject.assign(ruleOptionsEnable,' + JSON.stringify(options) + ');\nresult = ' + entry + '(input);', ctx, { timeout: 4000 });
  return clone(ctx.result);
}
let count = 0;
function test(name, check) { check(); count++; console.log('PASS ' + name); }

async function main() {
  const input = fixture(), base = evaluate(code, input, {}, 'buildBaseConfig'), current = evaluate(code, input);
  test('Generated full script is current and standalone ES2020', () => { assert.equal(generate(), code); build({ check: true }); espree.parse(code, { ecmaVersion: 2020, sourceType: 'script' }); });
  test('Bettbox options are editable static booleans with descriptions', () => {
    const ast = espree.parse(code, { ecmaVersion: 2020, sourceType: 'script', range: true });
    const declarations = ast.body.filter(node => node.type === 'VariableDeclaration').flatMap(node => node.declarations);
    const marker = declarations.find(node => node.id.name === 'Compatible_With_Bettbox');
    assert(code.slice(0, 2000).includes('Compatible_With_Bettbox'), 'Bettbox only scans the first 2000 characters');
    assert.equal(marker.init.properties[0].key.name, 'ruleOptionsEnable');
    assert.equal(marker.init.properties[0].value.value, true);
    const options = declarations.find(node => node.id.name === 'ruleOptionsEnable');
    assert.equal(options.init.type, 'ObjectExpression');
    assert(options.range[0] < declarations.find(node => node.id.name === 'ruleProviderDefinitions').range[0]);
    for (const entry of options.init.properties) {
      assert.equal(entry.type, 'Property');
      assert.equal(entry.computed, false);
      assert.equal(entry.value.type, 'Literal');
      assert.equal(typeof entry.value.value, 'boolean');
      assert(code.slice(entry.range[1]).split('\n')[0].includes('//'), entry.key.name + ': missing switch description');
    }
    const context = vm.createContext({});
    vm.runInContext(code + '\nmetadata = { options: ruleOptionsEnable, icons: Object.fromEntries(serviceConfigs.map(service => [service.name, service.icon])) };', context);
    for (const key of Object.keys(context.metadata.options)) assert.match(context.metadata.icons[key], /^https:\/\//, key + ': missing Bettbox switch icon');
    // The generated booleans also remain editable as ordinary script settings.
    const edited = code.replace(/(EHentai:\s*)true(,\s*\/\/)/, '$1false$2');
    assert.notEqual(edited, code);
    const result = evaluate(edited, input);
    assert(!result['proxy-groups'].some(group => group.name === 'EHentai'));
    assert.equal(result['rule-providers'].ehentai, undefined);
    assert(!Object.keys(result.dns['nameserver-policy']).some(key => key.includes('ehentai')));
    // Bettbox stores custom-options separately and assigns them before main.
    assert.deepEqual(evaluate(code, input, { EHentai: false }), result);
  });
  test('Personal additions preserve generic group behavior and connection settings', () => {
    const behavior = group => Object.fromEntries(Object.entries(group).filter(([key]) => !['icon', 'hidden'].includes(key)));
    for (const name of ['直接连接', '代理QUIC', '最低延迟', '故障转移']) assert.deepEqual(behavior(current['proxy-groups'].find(g => g.name === name)), behavior(base['proxy-groups'].find(g => g.name === name)));
    for (const key of ['proxies', 'sniffer', 'profile', 'experimental', 'ipv6', 'tcp-concurrent', 'unified-delay', 'keep-alive-interval']) assert.deepEqual(current[key], base[key]);
    for (const [name, rules] of Object.entries(base['sub-rules'])) assert.deepEqual(current['sub-rules'][name], rules);
    assert.deepEqual(current['proxy-providers'], base['proxy-providers']);
  });
  test('Application routing preserves personal priorities and aggregate fallbacks', () => {
    const replaced = new Set(['DST-PORT,5228-5230,直接连接', 'SUB-RULE,(RULE-SET,safe_ip),sub-safe']);
    assert.deepEqual(current.rules.filter(rule => base.rules.includes(rule)), base.rules.filter(rule => !replaced.has(rule)));
    assert(current.rules.indexOf('RULE-SET,ads,REJECT') < current.rules.indexOf('PROCESS-NAME,OneDrive.exe,OneDrive'));
    assert(current.rules.indexOf('PROCESS-NAME,OneDrive.exe,OneDrive') < current.rules.indexOf('DOMAIN,api.onedrive.com,直接连接'));
    assert(current.rules.indexOf('DOMAIN,login.microsoftonline.com,直接连接') < current.rules.indexOf('RULE-SET,proxy@direct,直接连接'));
    const fcm = current.rules.indexOf('SUB-RULE,(RULE-SET,googlefcm),sub-app-googlefcm');
    assert(current.rules.indexOf('DOMAIN,login.microsoftonline.com,直接连接') < fcm);
    assert(fcm < current.rules.indexOf('RULE-SET,proxy@direct,直接连接'));
    const portFallback = current.rules.indexOf('DST-PORT,5228-5230,FCM');
    assert(portFallback > current.rules.indexOf('RULE-SET,direct-lite,直接连接'));
    assert(portFallback < current.rules.findIndex(rule => rule.startsWith('SUB-RULE,(RULE-SET,telegram_ip,')));
    const guard = current.rules.indexOf('AND,((NETWORK,UDP),(RULE-SET,ai)),REJECT');
    for (const id of ['googlefcm', 'youtube', 'telegram', 'microsoft', 'steam', 'twitter', 'pikpak', 'ehentai']) {
      const index = current.rules.indexOf('SUB-RULE,(RULE-SET,' + id + '),sub-app-' + id);
      assert(index > guard, id + ': service routing must follow the AI UDP guard');
      assert(index < current.rules.indexOf('SUB-RULE,(RULE-SET,google),sub-google'), id + ': service routing must precede Google parent domains');
      assert(index < current.rules.indexOf('RULE-SET,proxy@direct,直接连接'), id + ': service routing must precede general direct exceptions');
    }
  });
  test('Steam and Google outrank broader infrastructure and download categories', () => {
    assert(current.rules.indexOf('SUB-RULE,(RULE-SET,steam),sub-app-steam') < current.rules.indexOf('SUB-RULE,(RULE-SET,microsoft),sub-app-microsoft'));
    assert(current.rules.indexOf('SUB-RULE,(RULE-SET,google),sub-google') < current.rules.indexOf('RULE-SET,proxy@direct,直接连接'));
    assert(current.rules.indexOf('SUB-RULE,(RULE-SET,google),sub-google') < current.rules.indexOf('SUB-RULE,(RULE-SET,download),sub-download'));
  });
  test('Apple, Meta and Line are opt-in while Netflix stays under overseas media', () => {
    const enabled = evaluate(code, input, { Apple: true, Meta: true, Line: true });
    for (const [name, id] of [['Apple', 'apple'], ['Meta', 'meta'], ['Line', 'line']]) {
      assert(!current['proxy-groups'].some(group => group.name === name), name + ': disabled by default');
      assert.equal(current['rule-providers'][id], undefined);
      assert(enabled['proxy-groups'].some(group => group.name === name));
      assert(enabled.rules.includes('SUB-RULE,(RULE-SET,' + id + '),sub-app-' + id));
      assert(enabled.dns['nameserver-policy']['rule-set:' + id].every(address => address.includes('#' + name)));
    }
    for (const cfg of [current, enabled]) {
      assert(!cfg['proxy-groups'].some(group => group.name === 'Netflix'));
      assert.equal(cfg['rule-providers'].netflix, undefined);
      assert(cfg.rules.includes('SUB-RULE,(RULE-SET,media),sub-media'));
      assert(cfg.rules.includes('SUB-RULE,(RULE-SET,media_ip),sub-media'));
      assert(cfg['sub-rules']['sub-media'].includes('MATCH,海外媒体'));
    }
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
    assert.equal(group.type, 'select'); assert.equal(group.proxies[0], '日本');
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
    assert.equal(off['find-process-mode'], base['find-process-mode']);
    assert(!off.rules.some(rule => rule.startsWith('PROCESS-NAME,')));
  });
  test('Disabling optional services removes their rules, groups and DNS policies', () => {
    const off = evaluate(code, input, { DLsite: false, 大流量下载直连: false, AI固定出口: false });
    assert(!off['proxy-groups'].some(g => ['DLsite', '下载更新'].includes(g.name)));
    assert.equal(off['rule-providers'].dlsite, undefined);
    assert(!Object.keys(off.dns['nameserver-policy']).some(k => k.includes('dlsite')));
    const normal = off['proxy-groups'].find(g => g.name === '国外AI');
    assert.equal(normal['include-all-providers'], true);
    assert(normal.proxies.includes('日本') && normal.proxies.includes('美国'));
    assert(!normal.proxies.includes('REJECT'));
  });
  test('DNS preserves base resolvers without forcing an unrelated ECS subnet', () => {
    for (const key of ['default-nameserver', 'direct-nameserver', 'prefer-h3', 'enhanced-mode', 'fake-ip-filter-mode']) assert.deepEqual(current.dns[key], base.dns[key]);
    assert.deepEqual(current.dns.nameserver, base.dns.nameserver.map(address => address.replace(/&ecs=[^&]+/g, '').replace(/&ecs-override=[^&]+/g, '')));
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
    assert.deepEqual(legacy.dns.nameserver, base.dns.nameserver);
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
  for (const file of ['src', 'config', 'Rules/personal']) fs.cpSync(path.join(root, file), path.join(dir, file), { recursive: true });
  test('Publication derives every provider from this repository manifest', () => {
    fs.writeFileSync(path.join(dir, 'config/project.json'), JSON.stringify({ repository: 'example/config', branch: 'main' }));
    const published = evaluate(generate(dir), input, { Apple: true, Meta: true, Line: true });
    const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'config/rule-sources.json'), 'utf8'));
    const httpProviders = Object.entries(published['rule-providers']).filter(([, provider]) => provider.type === 'http');
    assert.deepEqual(httpProviders.map(([id]) => id).sort(), Object.keys(manifest.rulesets).sort());
    for (const [id, provider] of httpProviders) {
      assert.equal(provider.url, 'https://raw.githubusercontent.com/example/config/main/Rules/generated/' + manifest.rulesets[id].behavior + '/' + id + '.mrs');
      assert.equal(provider.path, './rules/personal-' + id + '.mrs');
      assert.equal(provider.format, 'mrs');
      assert.equal(provider.interval, 86400);
      assert.equal(provider.proxy, '代理连接');
    }
  });
  test('Base providers and service providers are independent for each execution', () => {
    const ctx = vm.createContext({ input: fixture() });
    vm.runInContext(code + '\nfirst = main(input); first["rule-providers"].ads.url = "modified"; first["rule-providers"].dlsite.path = "modified"; second = main(input); base = buildBaseConfig(input);', ctx, { timeout: 4000 });
    assert.deepEqual(clone(ctx.second), current);
    assert.equal(ctx.base['rule-providers'].dlsite, undefined);
  });
  test('Missing routing and DNS providers prevent generating a release', () => {
    const file = path.join(dir, 'config/rule-sources.json');
    const originalManifest = fs.readFileSync(file, 'utf8');
    try {
      for (const id of ['telegram_ip', 'dnsmasq-china-lite', 'dlsite']) {
        const manifest = JSON.parse(originalManifest);
        delete manifest.rulesets[id];
        fs.writeFileSync(file, JSON.stringify(manifest));
        assert.throws(() => generate(dir), new RegExp('Missing rule provider definition: ' + id));
      }
      const manifest = JSON.parse(originalManifest);
      manifest.rulesets.ads.behavior = 'unknown';
      fs.writeFileSync(file, JSON.stringify(manifest));
      assert.throws(() => generate(dir), /Invalid published rule provider: ads/);
    } finally { fs.writeFileSync(file, originalManifest); }
  });
  test('References in sub-rules, DNS filters, policies and sniffer lists are checked', () => {
    for (const field of [
      { rules: ['AND,((NETWORK,UDP),(RULE-SET,missing)),REJECT'] },
      { 'sub-rules': { example: ['RULE-SET,missing,REJECT'] } },
      { dns: { 'fake-ip-filter': ['RULE-SET,missing,real-ip'] } },
      { dns: { 'nameserver-policy': { 'rule-set:known,missing': ['rcode://success'] } } },
      { sniffer: { 'skip-domain': ['rule-set:known,missing'] } },
    ]) assert.throws(() => validateProviderReferences({ 'rule-providers': { known: {} }, ...field }), /Missing rule provider definition: missing/);
  });
  test('Unconfigured and invalid publication repositories fail clearly', () => {
    const file = path.join(dir, 'config/project.json');
    const originalProject = fs.readFileSync(file, 'utf8');
    try {
      for (const project of [null, { repository: null, branch: 'main' }, { repository: 'https://github.com/example/config', branch: 'main' }, { repository: '../config', branch: 'main' }, { repository: 'example/..', branch: 'main' }, { repository: 'example/config', branch: '../main' }, { repository: 'example/config', branch: null }]) {
        fs.writeFileSync(file, JSON.stringify(project));
        assert.throws(() => generate(dir), /Invalid publication repository or branch/);
      }
    } finally { fs.writeFileSync(file, originalProject); }
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
