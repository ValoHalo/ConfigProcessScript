'use strict';

const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const espree = require('espree');
const fixtures = require('./lib/fixtures');

const source = fs.readFileSync(path.join(__dirname, '../src/personal-dns.js'), 'utf8');
const patchPersonalDns = vm.runInNewContext(source + '\n;patchPersonalDns;', {});
const clone = (value) => JSON.parse(JSON.stringify(value));
const groups = { direct: '直接连接', proxy: '代理连接', ai: '国外AI', dlsite: 'DLsite' };
const proxyDns = ['https://dns.google/dns-query#代理DNS&ecs=8.8.8.8/24&ecs-override=true', 'https://dns.quad9.net/dns-query#代理DNS&h3=false'];
const directDns = ['https://dns.alidns.com/dns-query#直接连接', 'https://doh.pub/dns-query#直接连接&h3=false'];
const node = (extra = {}) => ({ name: 'JP 01', type: 'trojan', server: 'node.example.net', port: 443, password: 'fixture', ...extra });
function upstream(input) {
  return {
    ipv6: true,
    tun: { enable: true, stack: 'mixed' },
    'proxy-providers': { 节点: { type: 'inline', payload: clone(input.proxies || []), override: { 'ip-version': 'dual' }, 'health-check': { interval: 600 } } },
    'proxy-groups': Object.values(groups).map((name) => ({ name, type: 'select', proxies: ['DIRECT'] })),
    hosts: { ...clone(input.hosts || {}), 'dns.google': ['8.8.8.8', '8.8.4.4'] },
    dns: {
      enable: true,
      'prefer-h3': true,
      'respect-rules': false,
      'use-system-hosts': false,
      'proxy-server-nameserver': clone(directDns),
      nameserver: clone(proxyDns),
      'default-nameserver': ['223.6.6.6', '119.29.29.29'],
      'nameserver-policy': {
        'rule-set:ads': ['rcode://name_error'],
        'rule-set:proxy@direct': clone(directDns),
        'rule-set:ai,download,safe,google,media,proxy-lite': clone(proxyDns),
        'rule-set:direct-lite,dnsmasq-china-lite': clone(directDns),
      },
      'direct-nameserver': clone(directDns),
      'direct-nameserver-follow-policy': true,
      'fake-ip-filter-mode': 'rule',
      'fake-ip-filter': ['RULE-SET,ads,fake-ip', 'RULE-SET,proxy@direct,real-ip', 'RULE-SET,ai,fake-ip', 'MATCH,fake-ip'],
    },
    'rule-providers': {
      ai: { type: 'http', behavior: 'domain', format: 'mrs', url: 'https://rules.example.net/ai.mrs', path: './rules/ai.mrs' },
      dlsite: { type: 'inline', behavior: 'domain', payload: ['+.dlsite.com'] },
    },
  };
}
function apply(input, settings = {}, base = upstream(input)) {
  const inputBefore = JSON.stringify(input);
  const baseBefore = JSON.stringify(base);
  const output = clone(patchPersonalDns(input, base, settings, groups));
  assert.equal(JSON.stringify(input), inputBefore, 'The subscription must remain unchanged');
  assert.equal(JSON.stringify(base), baseBefore, 'The upstream config must remain unchanged');
  for (const key of ['nameserver', 'default-nameserver', 'direct-nameserver', 'respect-rules', 'direct-nameserver-follow-policy', 'use-system-hosts']) {
    assert.deepEqual(output.dns[key], base.dns[key], 'General upstream DNS changed: ' + key);
  }
  return output;
}
let passed = 0;
function test(name, run) {
  run();
  passed++;
  console.log('PASS ' + name);
}

test('Personal DNS module uses ES2020 and runs without host imports', () => {
  espree.parse(source, { ecmaVersion: 2020 });
  assert.equal(typeof patchPersonalDns, 'function');
});

test('Missing subscription node DNS removes the base fallback without changing other settings', () => {
  const input = fixtures.minimalSubscription();
  const base = upstream(input);
  const expected = clone(base);
  delete expected.dns['proxy-server-nameserver'];
  assert.deepEqual(apply(input, {}, base), expected);
});

test('Private node policy is promoted without losing h3 or ECS parameters', () => {
  const resolver = 'https://private.example.org/dns-query#旧组&h3=false&ecs=192.0.2.0/24&ecs-override=true';
  const input = { proxies: [node()], dns: { 'nameserver-policy': { 'node.example.net': resolver } } };
  const out = apply(input);
  const expected = resolver.replace('#旧组', '#直接连接');
  assert.deepEqual(out.dns['proxy-server-nameserver'], [expected]);
  assert.equal(out.dns['proxy-server-nameserver-policy']['node.example.net'], expected);
});

test('Ordinary nameserver and unrelated policies are not promoted to node DNS', () => {
  const input = { proxies: [node()], dns: { nameserver: ['https://private.example.net/dns-query'], 'nameserver-policy': { 'unrelated.example.net': 'https://private.example.net/dns-query' } } };
  const out = apply(input);
  assert.equal(out.dns['proxy-server-nameserver'], undefined);
  assert.equal(out.dns['proxy-server-nameserver-policy'], undefined);
});

test('Public resolver recognition uses hostname rather than URL substrings', () => {
  const input = { proxies: [node()], dns: { 'nameserver-policy': { 'node.example.net': ['https://dns.google/dns-query#h3=false', 'tls://[2001:4860:4860:0:0:0:0:8888]', 'https://dns.google.private.example.net/dns-query#h3=true'] } } };
  const out = apply(input);
  assert.deepEqual(out.dns['proxy-server-nameserver'], ['https://dns.google.private.example.net/dns-query#直接连接&h3=true']);
});

test('Explicit node resolvers and exact policies retain their parameters and scope', () => {
  const input = { proxies: [node(), node({ name: 'US 01', server: 'other.example.net' })], dns: {
    'proxy-server-nameserver': ['https://dns.google/dns-query#DIRECT&h3=false', 'https://private.example.net/dns-query#旧策略&ecs=192.0.2.0/24'],
    'proxy-server-nameserver-policy': { 'node.example.net': 'https://node-dns.example.net/dns-query#DIRECT&h3=true' },
  } };
  const out = apply(input);
  assert(out.dns['proxy-server-nameserver'].includes('https://dns.google/dns-query#直接连接&h3=false'));
  assert(out.dns['proxy-server-nameserver'].includes('https://private.example.net/dns-query#直接连接&ecs=192.0.2.0/24'));
  assert.deepEqual(Object.keys(out.dns['proxy-server-nameserver-policy']), ['node.example.net']);
  assert.equal(out.dns['proxy-server-nameserver-policy']['node.example.net'], 'https://node-dns.example.net/dns-query#直接连接&h3=true');
});

test('A node policy rule-set collision receives a distinct provider and cache path', () => {
  const input = { proxies: [node()], dns: { 'proxy-server-nameserver-policy': { 'rule-set:ai,missing': ['https://private.example.net/dns-query#DIRECT&h3=false'] } }, 'rule-providers': {
    ai: { type: 'http', behavior: 'domain', format: 'mrs', url: 'https://subscription.example.net/nodes.mrs', path: './rules/ai.mrs', proxy: '失效组' },
  } };
  const base = upstream(input);
  base.dns['proxy-server-nameserver-policy'] = { 'rule-set:ai,missing': ['https://private.example.net/dns-query#直接连接'] };
  const out = apply(input, {}, base);
  assert.deepEqual(out['rule-providers'].ai, base['rule-providers'].ai);
  assert.equal(out['rule-providers']['personal-dns-ai'].url, input['rule-providers'].ai.url);
  assert.equal(out['rule-providers']['personal-dns-ai'].proxy, groups.direct);
  assert.notEqual(out['rule-providers']['personal-dns-ai'].path, out['rule-providers'].ai.path);
  assert.deepEqual(out.dns['proxy-server-nameserver-policy'], { 'rule-set:personal-dns-ai': ['https://private.example.net/dns-query#直接连接&h3=false'] });
});

test('The existing subscription fixture retains private policy through a hosts rewrite', () => {
  const input = fixtures.typicalSubscription();
  const out = apply(input);
  assert.equal(out['proxy-providers'].节点.payload[0].server, '10.0.0.1');
  assert(out.dns['proxy-server-nameserver'].includes('https://private.example-dns.com/dns-query#直接连接'));
  assert(out.dns['fake-ip-filter'].includes('DOMAIN,hk1.example.com,real-ip'));
  assert(!out.dns['fake-ip-filter'].some((rule) => rule.includes('www.unrelated.com')));
});

test('Single-address hosts preserve implicit and explicit TLS identities', () => {
  for (const type of ['vmess', 'vless', 'trojan', 'hysteria2', 'tuic', 'anytls']) {
    const input = { proxies: [node({ type, tls: true })], dns: { listen: '0.0.0.0:53', 'proxy-server-nameserver': ['127.0.0.1:53'] }, hosts: { 'node.example.net': '192.0.2.10' } };
    const out = apply(input);
    const mapped = out['proxy-providers'].节点.payload[0];
    assert.equal(mapped.server, '192.0.2.10');
    assert.equal(mapped[['vmess', 'vless'].includes(type) ? 'servername' : 'sni'], 'node.example.net');
    input.proxies[0][['vmess', 'vless'].includes(type) ? 'servername' : 'sni'] = 'explicit.example.net';
    const explicit = apply(input)['proxy-providers'].节点.payload[0];
    assert.equal(explicit[['vmess', 'vless'].includes(type) ? 'servername' : 'sni'], 'explicit.example.net');
  }
});

test('WS, gRPC and plugin nodes retain their transport identity through hosts', () => {
  for (const extra of [{ network: 'ws', 'ws-opts': { path: '/ws', headers: { Host: 'host.example.net' } } }, { network: 'grpc', 'grpc-opts': { 'grpc-service-name': 'service' } }, { plugin: 'obfs', 'plugin-opts': { host: 'plugin.example.net' } }]) {
    const input = { proxies: [node(extra)], dns: { listen: '0.0.0.0:53', 'proxy-server-nameserver': ['127.0.0.1:53'] }, hosts: { 'node.example.net': 'target.example.net' } };
    const out = apply(input);
    assert.deepEqual(out['proxy-providers'].节点.payload[0], input.proxies[0]);
    assert.equal(out.hosts['node.example.net'], 'target.example.net');
  }
});

test('Multiple IPv4 and IPv6 host addresses remain available to the core', () => {
  const addresses = ['192.0.2.10', '2001:db8::10'];
  const input = { proxies: [node()], dns: { listen: '[::]:53', 'proxy-server-nameserver': ['[::1]:53'] }, hosts: { 'node.example.net': addresses } };
  const out = apply(input);
  assert.equal(out['proxy-providers'].节点.payload[0].server, 'node.example.net');
  assert.deepEqual(out.hosts['node.example.net'], addresses);
  assert.deepEqual(out.dns['proxy-server-nameserver'], directDns);
});

test('A different local DNS port does not trigger a server rewrite', () => {
  const input = { proxies: [node()], dns: { listen: '0.0.0.0:53', 'proxy-server-nameserver': ['127.0.0.1:5353'] }, hosts: { 'node.example.net': '192.0.2.10' } };
  const out = apply(input);
  assert.equal(out['proxy-providers'].节点.payload[0].server, 'node.example.net');
  assert.deepEqual(out.dns['proxy-server-nameserver'], ['127.0.0.1:5353#直接连接']);
});

test('Hosts cycles fail explicitly instead of producing a broken node', () => {
  const input = { proxies: [node()], dns: { listen: '0.0.0.0:53', 'proxy-server-nameserver': ['127.0.0.1:53'] }, hosts: { 'node.example.net': 'other.example.net', 'other.example.net': 'node.example.net' } };
  assert.throws(() => patchPersonalDns(input, upstream(input), {}, groups), /hosts.*循环/);
});

test('Top-level subscription nodes receive the same host correction as inline providers', () => {
  const input = { proxies: [node()], dns: { listen: '0.0.0.0:53', 'proxy-server-nameserver': ['127.0.0.1:53'] }, hosts: { 'node.example.net': '192.0.2.10' } };
  const base = upstream(input);
  base.proxies = clone(input.proxies);
  delete base['proxy-providers'];
  assert.equal(apply(input, {}, base).proxies[0].sni, 'node.example.net');
});

test('Node fake-IP exceptions become exact real-IP rules before Echsfxy rules', () => {
  const input = { proxies: [node()], dns: { 'fake-ip-filter': ['+.example.net', '+.unrelated.net'] } };
  const base = upstream(input);
  const out = apply(input, {}, base);
  assert.equal(out.dns['fake-ip-filter'][0], 'DOMAIN,node.example.net,real-ip');
  assert.deepEqual(out.dns['fake-ip-filter'].slice(1), base.dns['fake-ip-filter']);
});

test('AI and DLsite DNS follow their groups without duplicate combined policies or lost ECS', () => {
  const input = fixtures.minimalSubscription();
  const out = apply(input, { dnsFollowServices: { ai: true, dlsite: true } });
  const policies = out.dns['nameserver-policy'];
  assert.equal(policies['rule-set:ai,download,safe,google,media,proxy-lite'], undefined);
  assert.deepEqual(policies['rule-set:download,safe,google,media,proxy-lite'], proxyDns);
  assert.deepEqual(policies['rule-set:ai'], proxyDns.map((address) => address.replace('#代理DNS', '#国外AI')));
  assert.deepEqual(policies['rule-set:dlsite'], proxyDns.map((address) => address.replace('#代理DNS', '#DLsite')));
  assert.deepEqual(Object.keys(policies).filter((key) => key.startsWith('rule-set:') && key.slice(9).split(',').includes('ai')), ['rule-set:ai']);
});

test('Disabling service DNS leaves the complete upstream nameserver policy unchanged', () => {
  const input = fixtures.minimalSubscription();
  const base = upstream(input);
  const out = apply(input, { dnsFollowServices: { ai: false, dlsite: false } }, base);
  assert.deepEqual(out.dns['nameserver-policy'], base.dns['nameserver-policy']);
});

test('An absent service group does not leave a dangling DNS route', () => {
  const input = fixtures.minimalSubscription();
  const base = upstream(input);
  base['proxy-groups'] = base['proxy-groups'].filter((group) => group.name !== groups.ai);
  const out = apply(input, { dnsFollowServices: { ai: true } }, base);
  assert.deepEqual(out.dns['nameserver-policy'], base.dns['nameserver-policy']);
});

test('Imported HTTPS node resolvers retain the source HTTP preference without adding ineffective URL parameters', () => {
  const input = { proxies: [node()], dns: {
    'proxy-server-nameserver': ['https://explicit.example.net:8080/dns-query#ecs=192.0.2.0/24'],
    'nameserver-policy': { 'node.example.net': 'https://private.example.net:8080/dns-query' },
    'proxy-server-nameserver-policy': { 'other.example.net': 'https://other.example.net/dns-query' },
  } };
  const out = apply(input);
  assert.equal(out.dns['prefer-h3'], false);
  assert(out.dns['proxy-server-nameserver'].every((address) => !address.includes('h3=')));
  assert.equal(out.dns['proxy-server-nameserver-policy']['node.example.net'], 'https://private.example.net:8080/dns-query#直接连接');
  assert.equal(out.dns['proxy-server-nameserver-policy']['other.example.net'], 'https://other.example.net/dns-query#直接连接');
});

test('Explicit HTTP/3 node resolver parameters and the source preference are preserved', () => {
  const input = { proxies: [node()], dns: {
    'nameserver-policy': { 'node.example.net': ['https://private.example.net/dns-query#h3=true&ecs=192.0.2.0/24', 'https://private2.example.net/dns-query#h3=false'] },
  } };
  const explicit = apply(input);
  assert.deepEqual(explicit.dns['proxy-server-nameserver'], ['https://private.example.net/dns-query#直接连接&h3=true&ecs=192.0.2.0/24', 'https://private2.example.net/dns-query#直接连接&h3=false']);
  assert.equal(explicit.dns['prefer-h3'], false);
  input.dns['prefer-h3'] = true;
  input.dns['nameserver-policy']['node.example.net'] = 'https://private.example.net/dns-query';
  const sourcePreference = apply(input);
  assert.deepEqual(sourcePreference.dns['proxy-server-nameserver'], ['https://private.example.net/dns-query#直接连接']);
  assert.equal(sourcePreference.dns['prefer-h3'], true);
});

test('Non-HTTPS node resolvers and an upstream without prefer-h3 gain no h3 parameter', () => {
  const input = { proxies: [node()], dns: { 'proxy-server-nameserver': ['tls://private.example.net', 'https://private.example.net/dns-query'] } };
  const base = upstream(input);
  base.dns['prefer-h3'] = false;
  const out = apply(input, {}, base);
  assert.deepEqual(out.dns['proxy-server-nameserver'], ['tls://private.example.net#直接连接', 'https://private.example.net/dns-query#直接连接']);
  assert.equal(apply(input).dns['proxy-server-nameserver'][0], 'tls://private.example.net#直接连接');
});

test('Only explicitly forced H3 node resolvers leave the upstream preference enabled', () => {
  const input = { proxies: [node()], dns: { 'nameserver-policy': { 'node.example.net': 'https://private.example.net/dns-query#h3=true&ecs=192.0.2.0/24' } } };
  const out = apply(input);
  assert.equal(out.dns['prefer-h3'], true);
  assert.deepEqual(out.dns['proxy-server-nameserver'], ['https://private.example.net/dns-query#直接连接&h3=true&ecs=192.0.2.0/24']);
});

test('Unrelated HTTPS policies and non-HTTPS node resolvers do not change prefer-h3', () => {
  const input = { proxies: [node()], dns: {
    'proxy-server-nameserver': ['tls://private.example.net'],
    'nameserver-policy': { 'unrelated.example.net': 'https://other.example.net/dns-query' },
  } };
  assert.equal(apply(input).dns['prefer-h3'], true);
});

const overseasNodeDns = [
  'https://odvr.nic.cz/doh#DIRECT',
  'https://dns.digitale-gesellschaft.ch/dns-query#DIRECT',
  'https://doh.applied-privacy.net/query#DIRECT',
];
test('Domestic-only node DNS becomes three direct overseas DoH resolvers', () => {
  for (const addresses of [
    ['223.5.5.5', '119.29.29.29'],
    ['https://DNS.ALIDNS.COM/dns-query#旧组&h3=true', 'https://doh.pub/dns-query'],
    ['tls://[2400:3200:0:0:0:0:0:1]', 'https://[2402:4e00:1::]/dns-query'],
    ['114.114.115.115', '210.2.4.8'],
    'https://doh.pub/dns-query',
  ]) {
    const out = apply({ proxies: [node()], dns: { 'prefer-h3': true, 'proxy-server-nameserver': addresses } });
    assert.deepEqual(out.dns['proxy-server-nameserver'], overseasNodeDns);
    assert.equal(out.dns['prefer-h3'], false);
  }
});
test('Empty and ordinary DNS lists do not create node DNS', () => {
  for (const dns of [undefined, {}, { 'proxy-server-nameserver': [] }, { 'proxy-server-nameserver': '' }, { nameserver: ['223.5.5.5'] }]) {
    const out = apply({ proxies: [node()], dns });
    assert(!Object.hasOwn(out.dns, 'proxy-server-nameserver'));
  }
});
test('Foreign, mixed and private explicit resolvers retain addresses and parameters', () => {
  for (const addresses of [
    ['https://dns.google/dns-query#DIRECT&h3=false'],
    ['223.5.5.5', '8.8.8.8'],
    ['223.5.5.5', 'https://private.example.net/dns-query#ecs=192.0.2.0/24'],
    ['https://alidns.com.example.net/dns-query', 'https://provider.example.net/223.5.5.5'],
    overseasNodeDns,
  ]) {
    const out = apply({ proxies: [node()], dns: { 'proxy-server-nameserver': addresses } });
    assert.deepEqual(out.dns['proxy-server-nameserver'], addresses.map(address => {
      const [url, suffix = ''] = address.split('#');
      return url + '#直接连接' + suffix.split('&').filter(part => part.includes('=')).map(part => '&' + part).join('');
    }));
  }
});
test('Domestic node policies retain their keys and provide the required default node list', () => {
  for (const key of ['nameserver-policy', 'proxy-server-nameserver-policy']) {
    const input = { proxies: [node()], dns: { [key]: { 'node.example.net': '223.5.5.5' } } };
    const out = apply(input);
    assert.deepEqual(out.dns['proxy-server-nameserver-policy'], { 'node.example.net': overseasNodeDns });
    assert.deepEqual(out.dns['proxy-server-nameserver'], overseasNodeDns);
  }
  const unrelated = apply({ proxies: [node()], dns: { 'nameserver-policy': { 'other.example.net': '223.5.5.5' } } });
  assert.equal(unrelated.dns['proxy-server-nameserver-policy'], undefined);
});
test('Domestic node rule-set policy replacement retains dependencies', () => {
  const out = apply({ proxies: [node()], dns: { 'proxy-server-nameserver-policy': { 'rule-set:airport': ['119.29.29.29'] } },
    'rule-providers': { airport: { type: 'inline', behavior: 'domain', payload: ['+.example.net'] } } });
  assert.deepEqual(out.dns['proxy-server-nameserver-policy']['rule-set:airport'], overseasNodeDns);
  assert.deepEqual(out['rule-providers'].airport.payload, ['+.example.net']);
  assert.deepEqual(out.dns['proxy-server-nameserver'], overseasNodeDns);
});

const args = process.argv.slice(2);
if (args.length) {
  if (args.length !== 2 || args[0] !== '--mihomo') throw new Error('Usage: [--mihomo <official Mihomo executable>]');
  const { spawnSync } = require('node:child_process');
  const YAML = require('yaml');
  const { loadScript } = require('./lib/loader');
  const binary = path.resolve(args[1]);
  const api = loadScript('Script/mihomoScript.js');
  const parent = path.resolve(__dirname, '../.test-runtime');
  fs.mkdirSync(parent, { recursive: true });
  const directory = fs.mkdtempSync(path.join(parent, 'node-dns-load-'));
  for (const [name, dns] of Object.entries({
    absent: undefined,
    domestic: { 'proxy-server-nameserver': ['223.5.5.5'] },
    policy: { 'proxy-server-nameserver-policy': { 'node.example.net': '119.29.29.29' } },
    ruleset: { 'proxy-server-nameserver-policy': { 'rule-set:airport': '223.5.5.5' } },
  })) {
    test('Mihomo accepts generated node DNS: ' + name, () => {
      const output = api.main({ proxies: [node()], dns,
        'rule-providers': { airport: { type: 'inline', behavior: 'domain', payload: ['+.example.net'] } } });
      // Keep the generated configuration, using local rule fixtures to avoid network downloads.
      for (const [id, provider] of Object.entries(output['rule-providers'])) {
        output['rule-providers'][id] = { type: 'inline', behavior: provider.behavior,
          payload: provider.behavior === 'ipcidr' ? ['192.0.2.0/24'] :
            provider.behavior === 'classical' ? ['DOMAIN,example.invalid'] : ['+.example.invalid'] };
      }
      const file = path.join(directory, name + '.yaml');
      fs.writeFileSync(file, YAML.stringify(output));
      const result = spawnSync(binary, ['-t', '-d', directory, '-f', file], {
        encoding: 'utf8', windowsHide: true, timeout: 15000,
      });
      assert.equal(result.status, 0, String(result.error || '') + result.stdout + result.stderr);
    });
  }
}

console.log(`Personal DNS: ${passed} passed.`);
