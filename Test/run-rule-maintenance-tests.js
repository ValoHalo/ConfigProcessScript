#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const http = require('node:http');
const net = require('node:net');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { createHash } = require('node:crypto');
const { updateRules, validateConfig, normalizeDomain, parseEntries, parseCIDR, mergeEntries, pruneCovered, coversDomain, requestHeaders } = require('../Tools/update-rules');
const execFileAsync = promisify(execFile);
let checks = 0;

async function test(name, run) {
  await run();
  checks++;
  console.log('ok ' + checks + ' - ' + name);
}

function normalize(values, behavior = 'domain') {
  return parseEntries(Buffer.from(values.join('\n')), 'text', behavior, 'fixture');
}

async function snapshot(directory) {
  const result = {};
  async function visit(relative) {
    for (const entry of await fs.readdir(path.join(directory, relative), { withFileTypes: true })) {
      const next = path.join(relative, entry.name);
      if (entry.isDirectory()) await visit(next);
      else result[next] = (await fs.readFile(path.join(directory, next))).toString('base64');
    }
  }
  await visit('');
  return result;
}

async function recipeTests(parent, origin, responses) {
  const root = path.join(parent, 'recipe-fixture');
  const configFile = path.join(root, 'config', 'rule-sources.json');
  const generated = path.join(root, 'Rules', 'generated');
  const sourceFile = path.join(root, 'Rules', 'sources', 'local.list');
  const addFile = path.join(root, 'Rules', 'overrides', 'add.list');
  const removeFile = path.join(root, 'Rules', 'overrides', 'remove.list');
  const remoteText = '+.cover.test\nkeep.test\nremove.test\n';
  responses.set('/recipe-source', { body: remoteText });
  responses.set('/recipe-other', { body: remoteText });
  const config = { version: 2, components: {
    seed: { behavior: 'domain', steps: [{ op: 'add', sources: [{ url: origin + '/recipe-source', format: 'text' }, { file: 'Rules/sources/local.list', format: 'text' }, { file: 'Rules/sources/empty.list', format: 'text' }] }] },
  }, rulesets: {
    domains: { behavior: 'domain', steps: [
      { op: 'add', sources: [{ ref: 'seed' }] },
      { op: 'prune-covered', sources: [{ entries: ['remove.test', 'child.cover.test'] }] },
      { op: 'add', sources: [{ entries: ['remove.test'] }] },
    ], add: ['Rules/overrides/add.list'], remove: ['Rules/overrides/remove.list'], minEntries: 1 },
    reference: { behavior: 'domain', steps: [{ op: 'add', sources: [{ ref: 'domains' }] }], minEntries: 1 },
  } };
  const save = () => fs.writeFile(configFile, JSON.stringify(config, null, 2) + '\n');
  const compile = async (_, args) => fs.copyFile(args[3], args[4]);
  const run = (options = {}) => updateRules({ root, timeout: 2000, mihomo: 'fixture', compile, ...options });
  await fs.mkdir(path.dirname(configFile), { recursive: true });
  await fs.mkdir(path.dirname(sourceFile), { recursive: true });
  await fs.mkdir(path.dirname(addFile), { recursive: true });
  await fs.writeFile(sourceFile, '# local\nlocal.test\n');
  await fs.writeFile(path.join(root, 'Rules', 'sources', 'empty.list'), '# intentionally empty\n');
  await fs.writeFile(addFile, '# additions\nadded.test\n');
  await fs.writeFile(removeFile, '# removals\nlocal.test\n');
  await save();
  await test('version 2 composes ordered recipes, shared components and published references without publishing helpers', async () => {
    const result = await run();
    assert.equal(result.manifest.version, 2);
    assert.deepEqual(Object.keys(result.manifest.rulesets), ['domains', 'reference']);
    assert.deepEqual(Object.keys(result.manifest.components), ['seed']);
    assert.equal(result.manifest.components.seed.output, undefined);
    assert.deepEqual((await fs.readdir(path.join(generated, 'domain'))).sort(), ['domains.list', 'domains.mrs', 'reference.list', 'reference.mrs']);
    const body = await fs.readFile(path.join(generated, 'domain', 'domains.list'), 'utf8');
    assert.equal(body, '+.cover.test\nadded.test\nkeep.test\nremove.test\n');
    assert.equal(await fs.readFile(path.join(generated, 'domain', 'reference.list'), 'utf8'), body);
    assert.equal(result.manifest.rulesets.domains.steps[1].removed, 1);
    assert.equal(result.manifest.rulesets.domains.steps[1].partialOverlap, 1);
    assert.equal(result.manifest.rulesets.domains.sources.filter((source) => source.url).length, 1);
    assert.equal((await run()).changed, false);
  });
  await test('reference validation rejects cycles, missing references and behavior mismatches before downloads', () => {
    let invalid = structuredClone(config);
    invalid.components.seed.steps[0].sources = [{ ref: 'reference' }];
    assert.throws(() => validateConfig(invalid), /reference cycle/);
    invalid = structuredClone(config);
    invalid.rulesets.domains.steps[0].sources = [{ ref: 'missing' }];
    assert.throws(() => validateConfig(invalid), /unknown reference/);
    invalid = structuredClone(config);
    invalid.components.seed.behavior = 'ipcidr';
    assert.throws(() => validateConfig(invalid), /behavior mismatch/);
    invalid = structuredClone(config);
    invalid.components.seed.steps[0].sources = [{ url: origin + '/recipe-source', file: 'Rules/sources/local.list', format: 'text' }];
    assert.throws(() => validateConfig(invalid), /exactly one/);
  });
  await test('clean LF and Windows CRLF local sources and personal overrides have identical hashes', async () => {
    const before = await snapshot(generated);
    for (const filename of [sourceFile, addFile, removeFile]) {
      await fs.writeFile(filename, (await fs.readFile(filename, 'utf8')).replace(/\n/g, '\r\n'));
    }
    await run({ check: true });
    assert.equal((await run()).changed, false);
    assert.deepEqual(await snapshot(generated), before);
    for (const filename of [sourceFile, addFile, removeFile]) await fs.writeFile(filename, (await fs.readFile(filename, 'utf8')).replace(/\r\n/g, '\n'));
    await run({ check: true });
  });
  await test('offline generated checks need no downloaded cache and detect changed local recipe inputs', async () => {
    const cache = path.join(root, '.cache', 'rule-sources');
    const moved = path.join(root, '.cache', 'saved-sources');
    await fs.rename(cache, moved);
    try {
      await run({ check: true });
      await fs.appendFile(sourceFile, 'changed.test\n');
      await assert.rejects(run({ check: true }), /local source is out of date/);
      await fs.writeFile(sourceFile, '# local\nlocal.test\n');
      await run({ check: true });
    } finally { await fs.rename(moved, cache); }
  });
  await test('manifest source identity and recipe steps are independently verified', async () => {
    const filename = path.join(generated, 'manifest.json');
    const body = await fs.readFile(filename, 'utf8');
    try {
      let manifest = JSON.parse(body);
      manifest.components.seed.sources[0].url = origin + '/recipe-other';
      await fs.writeFile(filename, JSON.stringify(manifest));
      await assert.rejects(run({ check: true }), /source identity/);
      manifest = JSON.parse(body);
      manifest.rulesets.domains.sources = manifest.rulesets.domains.sources.filter((source) => !source.file);
      await fs.writeFile(filename, JSON.stringify(manifest));
      await assert.rejects(run({ check: true }), /source identity/);
      manifest = JSON.parse(body);
      manifest.rulesets.domains.steps[1].op = 'add';
      await fs.writeFile(filename, JSON.stringify(manifest));
      await assert.rejects(run({ check: true }), /steps do not match/);
    } finally { await fs.writeFile(filename, body); }
    await run({ check: true });
  });
  await test('component override checks detect a changed helper input before accepting existing outputs', async () => {
    const helper = path.join(root, 'Rules', 'overrides', 'component.list');
    await fs.writeFile(helper, '# helper input\n');
    config.components.seed.add = ['Rules/overrides/component.list'];
    await save();
    await run();
    await fs.appendFile(helper, 'helper.test\n');
    await assert.rejects(run({ check: true }), /seed: generated override is out of date/);
    await fs.writeFile(helper, '# helper input\r\n');
    await run({ check: true });
    delete config.components.seed.add;
    await save();
    await run();
  });
  await test('source URLs and ordered recipe edits are part of the checked build identity', async () => {
    const source = config.components.seed.steps[0].sources[0];
    source.url = origin + '/recipe-other';
    await save();
    await assert.rejects(run({ check: true }), /recipe configuration is out of date/);
    await assert.rejects(run({ offline: true }), /No verified cache/);
    source.url = origin + '/recipe-source';
    const first = config.rulesets.domains.steps[1];
    config.rulesets.domains.steps[1] = config.rulesets.domains.steps[2];
    config.rulesets.domains.steps[2] = first;
    await save();
    await assert.rejects(run({ check: true }), /recipe configuration is out of date/);
    config.rulesets.domains.steps.reverse();
    config.rulesets.domains.steps.unshift(config.rulesets.domains.steps.pop());
    await save();
    await run({ check: true });
  });
  await test('downloaded source hashes retain original bytes while local hashes normalize line endings', async () => {
    const before = JSON.parse(await fs.readFile(path.join(generated, 'manifest.json'), 'utf8'));
    responses.set('/recipe-source', { body: remoteText.replace(/\n/g, '\r\n') });
    const result = await run();
    assert.equal(result.changed, true);
    assert.notEqual(result.manifest.components.seed.sources[0].sha256, before.components.seed.sources[0].sha256);
    assert.equal(result.manifest.rulesets.domains.output.sha256, before.rulesets.domains.output.sha256);
    responses.set('/recipe-source', { body: remoteText });
    await run();
  });
  await test('HTTP 403 never silently uses cache or changes the existing recipe publication', async () => {
    const before = await snapshot(generated);
    responses.set('/recipe-source', { status: 403, body: 'Forbidden' });
    await assert.rejects(run(), /HTTP status 403/);
    assert.deepEqual(await snapshot(generated), before);
    await run({ check: true });
    responses.set('/recipe-source', { body: remoteText });
  });
  await test('strict personal exclusions still reject partial holes after permissive recipe pruning', async () => {
    const before = await snapshot(generated);
    await fs.appendFile(removeFile, 'child.cover.test\n');
    await assert.rejects(run(), /routing exception/);
    assert.deepEqual(await snapshot(generated), before);
    await fs.writeFile(removeFile, '# removals\nlocal.test\n');
    await run({ check: true });
  });
}

async function main() {
  await test('exact, suffix and single-label wildcard domain semantics remain distinct', () => {
    assert.deepEqual(mergeEntries(normalize(['EXAMPLE.com.', '*.example.com', 'foo.example.com', 'deep.foo.example.com']), [], 'domain'), ['*.example.com', 'deep.foo.example.com', 'example.com']);
    assert.deepEqual(mergeEntries(normalize(['+.example.com', '*.example.com', 'example.com', 'foo.example.com', '+.foo.example.com', 'unrelated.test']), [], 'domain'), ['+.example.com', 'unrelated.test']);
    assert(!coversDomain('*.example.com', 'example.com'));
    assert(!coversDomain('*.example.com', 'deep.foo.example.com'));
    assert(coversDomain('*.example.com', 'foo.example.com'));
  });
  await test('general wildcard labels, including bare star, do not erase unrelated domains', () => {
    assert.deepEqual(mergeEntries(normalize(['*', 'lan', 'time.*.com', 'time.apple.com', 'sub.time.apple.com', '+.stun.*.*', 'stun.host.test', 'sub.stun.host.test', 'ordinary.example.com']), [], 'domain'), ['*', '+.stun.*.*', 'ordinary.example.com', 'sub.time.apple.com', 'time.*.com']);
    assert(!coversDomain('*', 'example.com'));
    assert(coversDomain('+.stun.*.*', 'deep.stun.host.test'));
  });
  await test('domain exclusions remove complete coverage and reject unrepresentable holes', () => {
    assert.deepEqual(mergeEntries(normalize(['foo.example.com', '*.other.test', '+.kept.test']), normalize(['+.example.com']), 'domain'), ['*.other.test', '+.kept.test']);
    assert.throws(() => mergeEntries(normalize(['+.example.com']), normalize(['ads.example.com']), 'domain'), /routing exception/);
    assert.throws(() => mergeEntries(normalize(['*.example.com']), normalize(['+.foo.example.com']), 'domain'), /routing exception/);
    assert.throws(() => mergeEntries(normalize(['time.*.com']), normalize(['time.example.com']), 'domain'), /routing exception/);
    assert.deepEqual(mergeEntries(normalize(['*.example.com']), normalize(['deep.foo.example.com']), 'domain'), ['*.example.com']);
  });
  await test('IDNA domains normalize while URLs, whitespace and malformed labels fail', () => {
    assert.equal(normalizeDomain('例子.中国'), 'xn--fsqu00a.xn--fiqs8s');
    assert.equal(normalizeDomain('+.103.179.189.35'), '+.103.179.189.35');
    for (const value of ['example.com/path', 'foo?bar', 'foo#bar', 'foo%20bar', 'Mijia Cloud', '-bad.example', 'a..example', 'foo,bar', 'bad*label.test', '+.']) {
      assert.throws(() => normalizeDomain(value), /Invalid domain/);
    }
  });
  await test('IPv4 and IPv6 normalize host bits, zero runs, mapped addresses and deduplication', () => {
    assert.equal(parseCIDR('192.0.2.7/24').text, '192.0.2.0/24');
    assert.equal(parseCIDR('2001:0DB8:0000:0000:0000:0000:0000:0001/64').text, '2001:db8::/64');
    assert.equal(parseCIDR('::ffff:192.0.2.1/128').text, '::ffff:c000:201/128');
    assert.equal(parseCIDR('::/0').text, '::/0');
    assert.deepEqual(mergeEntries(normalize(['192.0.2.128/25', '192.0.2.7/24', '2001:db8::1/128', '2001:db8::/32'], 'ipcidr'), [], 'ipcidr'), ['192.0.2.0/24', '2001:db8::/32']);
    for (const value of ['300.1.1.1/24', '1.2.3.4/33', '1.2.3.4/-1', '::/129', 'fe80::1%4/64']) assert.throws(() => parseCIDR(value));
  });
  await test('IP exclusions remove whole networks and explicitly reject partial subnets', () => {
    assert.deepEqual(mergeEntries(normalize(['192.0.2.0/25', '2001:db8::/32'], 'ipcidr'), normalize(['192.0.2.0/24'], 'ipcidr'), 'ipcidr'), ['2001:db8::/32']);
    assert.throws(() => mergeEntries(['192.0.2.0/24'], ['192.0.2.0/25'], 'ipcidr'), /partial subnet/);
    assert.throws(() => mergeEntries(['2001:db8::/32'], ['2001:db8::/64'], 'ipcidr'), /partial subnet/);
  });
  await test('adjacent IPv4 and IPv6 siblings collapse repeatedly without spanning gaps or misaligned boundaries', () => {
    assert.deepEqual(mergeEntries(['192.0.2.0/26', '192.0.2.64/26', '192.0.2.128/26', '192.0.2.192/26'], [], 'ipcidr'), ['192.0.2.0/24']);
    assert.deepEqual(mergeEntries(['192.0.2.64/26', '192.0.2.128/26'], [], 'ipcidr'), ['192.0.2.64/26', '192.0.2.128/26']);
    assert.deepEqual(mergeEntries(['192.0.2.0/26', '192.0.2.128/26'], [], 'ipcidr'), ['192.0.2.0/26', '192.0.2.128/26']);
    assert.deepEqual(mergeEntries(['2001:db8::/65', '2001:db8:0:0:8000::/65'], [], 'ipcidr'), ['2001:db8::/64']);
    assert.deepEqual(mergeEntries(['0.0.0.0/1', '128.0.0.0/1', '::/1', '8000::/1'], [], 'ipcidr'), ['0.0.0.0/0', '::/0']);
    for (let seed = 1; seed <= 12; seed++) {
      const included = Array.from({ length: 256 }, (_, index) => ((index * seed + seed * 7) % 19) < 11);
      const ranges = mergeEntries(included.flatMap((keep, index) => keep ? ['192.0.2.' + index + '/32'] : []), [], 'ipcidr').map(parseCIDR);
      for (let index = 0; index < 256; index++) {
        const address = parseCIDR('192.0.2.' + index).start;
        assert.equal(ranges.some((range) => range.start <= address && range.end >= address), included[index]);
      }
    }
  });
  await test('YAML and classical domain lists parse without importing routing targets', () => {
    assert.deepEqual(parseEntries(Buffer.from('payload:\n  - "+.EXAMPLE.com"\n  - exact.test\n'), 'yaml', 'domain', 'yaml'), ['+.example.com', 'exact.test']);
    assert.deepEqual(parseEntries(Buffer.from('DOMAIN,exact.test,DIRECT\nDOMAIN-SUFFIX,example.com,Proxy\n'), 'classical-text', 'domain', 'classical'), ['exact.test', '+.example.com']);
    assert.throws(() => parseEntries(Buffer.from('IP-CIDR,192.0.2.0/24,DIRECT\n'), 'classical-text', 'domain', 'classical'), /unsupported classical/);
    assert.throws(() => parseEntries(Buffer.from('payload: [true]'), 'yaml', 'domain', 'yaml'), /invalid entry/);
    assert.throws(() => parseEntries(Buffer.from('<!doctype html><html>'), 'text', 'domain', 'html'), /HTML/);
    assert.throws(() => parseEntries(Buffer.from([0xff, 0xfe]), 'text', 'domain', 'encoding'), /UTF-8/);
  });
  await test('nonstandard DNS literals require a source-specific exact whitelist', () => {
    assert.deepEqual(parseEntries(Buffer.from('Mijia Cloud\nnormal.test\n'), 'text', 'domain', 'literal', false, ['Mijia Cloud']), ['mijia cloud', 'normal.test']);
    assert.throws(() => parseEntries(Buffer.from('Mijia Cloud\n'), 'text', 'domain', 'literal'), /invalid entry/);
    assert.throws(() => parseEntries(Buffer.from('Other Cloud\n'), 'text', 'domain', 'literal', false, ['Mijia Cloud']), /invalid entry/);
  });
  await test('dnsmasq and plain suffix sources preserve their suffix semantics', () => {
    assert.deepEqual(parseEntries(Buffer.from('# comment\nserver=/EXAMPLE.cn/114.114.114.114\n'), 'dnsmasq', 'domain', 'dnsmasq'), ['+.example.cn']);
    assert.deepEqual(parseEntries(Buffer.from('EXAMPLE.test\n*.other.test\n'), 'text', 'domain', 'suffix', false, [], 'suffix'), ['+.example.test', '+.other.test']);
    assert.throws(() => parseEntries(Buffer.from('address=/bad.test/0.0.0.0'), 'dnsmasq', 'domain', 'dnsmasq'), /invalid dnsmasq/);
  });
  await test('GitHub metadata extracts the selected domain fields and never imports IPs or unrelated fields', () => {
    const body = { web: ['192.0.2.0/24'], domains: { website: ['github.com'], copilot: ['*.githubcopilot.com'], actions_inbound: { full: ['*.actions.githubusercontent.com'] }, unrelated: ['excluded.test'] } };
    assert.deepEqual(parseEntries(Buffer.from(JSON.stringify(body)), 'github-meta', 'domain', 'metadata'), ['github.com', '+.githubcopilot.com', '+.actions.githubusercontent.com']);
    assert.throws(() => parseEntries(Buffer.from('{"domains":{"unrelated":["excluded.test"]}}'), 'github-meta', 'domain', 'metadata'), /empty/);
    assert.throws(() => parseEntries(Buffer.from('{}'), 'github-meta', 'domain', 'metadata'), /must contain domains/);
  });
  await test('FaaS JSON extracts only result arrays and retains IPv4/IPv6 address sizes', () => {
    const body = { cn: { note: 'ignored', result: { ipv4: ['192.0.2.1', '198.51.100.7/24'], ipv6: ['2001:db8::1'] } }, hk: { result: { ips: ['203.0.113.1'] } } };
    assert.deepEqual(parseEntries(Buffer.from(JSON.stringify(body)), 'faas-ip', 'ipcidr', 'FaaS'), ['192.0.2.1/32', '198.51.100.0/24', '2001:db8::1/128', '203.0.113.1/32']);
    assert.throws(() => parseEntries(Buffer.from('{}'), 'faas-ip', 'ipcidr', 'FaaS'), /empty/);
  });
  await test('recipe pruning preserves partial domain holes and reports them separately from removals', () => {
    const result = pruneCovered(['+.kept.test', 'removed.test', '*.overlap.test', '*.nested.test', 'deep.foo.untouched.test'], ['child.kept.test', '+.removed.test', '+.foo.overlap.test', 'deep.foo.nested.test', '*.untouched.test'], 'domain');
    assert.deepEqual(result.entries, ['*.nested.test', '*.overlap.test', '+.kept.test', 'deep.foo.untouched.test']);
    assert.deepEqual(result.diagnostics, { removed: 1, partialOverlap: 2 });
    assert.throws(() => mergeEntries(['+.kept.test'], ['child.kept.test'], 'domain'), /routing exception/);
  });
  await test('recipe pruning handles IPv4/IPv6 containment while retaining partial subnet overlap', () => {
    const result = pruneCovered(['192.0.2.0/24', '198.51.100.0/25', '2001:db8::/32'], ['192.0.2.0/25', '198.51.100.0/24', '2001:db8::/64'], 'ipcidr');
    assert.deepEqual(result.entries, ['192.0.2.0/24', '2001:db8::/32']);
    assert.deepEqual(result.diagnostics, { removed: 1, partialOverlap: 2 });
  });
  await test('domain pruning indexes agree with direct wildcard/coverage semantics', () => {
    const candidates = ['*', '+.*', '*.test', '+.test', 'a.test', '*.a.test', '+.a.test', 'deep.a.test', '+.deep.a.test', 'time.*.com', 'time.example.com', 'sub.time.example.com'];
    for (const entry of candidates) for (const removal of candidates) {
      const result = pruneCovered([entry], [removal], 'domain');
      assert.equal(result.diagnostics.removed, Number(coversDomain(removal, entry)), entry + ' pruned by ' + removal);
      if (result.entries.length) {
        let partial = false;
        try { mergeEntries([entry], [removal], 'domain'); } catch { partial = true; }
        assert.equal(result.diagnostics.partialOverlap, Number(partial), entry + ' overlaps ' + removal);
      }
    }
  });
  await test('GitHub credentials are scoped to the HTTPS API origin and are absent on redirect targets', () => {
    const previous = process.env.GITHUB_TOKEN;
    process.env.GITHUB_TOKEN = 'fixture-secret';
    try {
      assert.equal(requestHeaders('https://api.github.com/meta').Authorization, 'Bearer fixture-secret');
      for (const url of ['https://raw.githubusercontent.com/a/b', 'http://api.github.com/meta', 'https://api.github.com.example.test/meta', 'https://example.test/redirect', 'https://api.github.com:444/meta']) assert.equal(requestHeaders(url).Authorization, undefined);
    } finally { if (previous === undefined) delete process.env.GITHUB_TOKEN; else process.env.GITHUB_TOKEN = previous; }
  });

  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'rule-maintenance-'));
  const responses = new Map();
  const hits = new Map();
  let activeRequests = 0;
  let peakRequests = 0;
  const server = http.createServer((request, response) => {
    activeRequests++;
    peakRequests = Math.max(peakRequests, activeRequests);
    hits.set(request.url, (hits.get(request.url) || 0) + 1);
    const fixture = responses.get(request.url) || { status: 404, body: 'missing' };
    setTimeout(() => {
      activeRequests--;
      response.writeHead(fixture.status || 200, fixture.headers || { 'Content-Type': 'text/plain' });
      response.end(fixture.body);
    }, fixture.delay || 0);
  });
  const proxySockets = new Set();
  let proxyConnections = 0;
  const proxy = http.createServer();
  proxy.on('connect', (request, connection, head) => {
    proxyConnections++;
    const [hostname, port] = request.url.split(':');
    const upstream = net.connect({ host: hostname, port: Number(port) }, () => {
      connection.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length) upstream.write(head);
      connection.pipe(upstream);
      upstream.pipe(connection);
    });
    for (const socket of [connection, upstream]) {
      proxySockets.add(socket);
      socket.on('close', () => proxySockets.delete(socket));
      socket.on('error', () => { connection.destroy(); upstream.destroy(); });
    }
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  await new Promise((resolve) => proxy.listen(0, '127.0.0.1', resolve));
  const origin = 'http://127.0.0.1:' + server.address().port;
  const proxyURL = 'http://127.0.0.1:' + proxy.address().port;
  let config;
  const configFile = path.join(root, 'config', 'rule-sources.json');
  const generated = path.join(root, 'Rules', 'generated');
  const saveConfig = () => fs.writeFile(configFile, JSON.stringify(config));
  const setDomains = (body) => responses.set('/domains', { body });
  const defaultDomains = 'alpha.test\nbeta.test\ngamma.test\ndelta.test\n';
  const sourceURL = origin + '/domains';
  const run = (options = {}) => updateRules({ root, timeout: 2000, ...options });
  try {
    await fs.mkdir(path.join(root, 'config'), { recursive: true });
    await fs.mkdir(path.join(root, 'Rules', 'overrides'), { recursive: true });
    await fs.writeFile(path.join(root, 'Rules', 'overrides', 'domains.add.txt'), '# local rules\nlocal.test\n');
    await fs.writeFile(path.join(root, 'Rules', 'overrides', 'domains.remove.txt'), 'beta.test\n');
    setDomains(defaultDomains);
    responses.set('/ips', { body: 'payload:\n - 192.0.2.7/24\n - 2001:db8::1/64\n' });
    config = { version: 1, rulesets: {
      domains: { behavior: 'domain', sources: [{ url: sourceURL, format: 'text' }], add: ['Rules/overrides/domains.add.txt'], remove: ['Rules/overrides/domains.remove.txt'], minEntries: 1 },
      ips: { behavior: 'ipcidr', sources: [{ url: origin + '/ips', format: 'yaml' }], minEntries: 1 },
    } };
    await saveConfig();
    await test('network update merges overrides and writes deterministic source/output hashes', async () => {
      const result = await run();
      assert.equal(result.changed, true);
      assert.equal(await fs.readFile(path.join(generated, 'domain', 'domains.list'), 'utf8'), 'alpha.test\ndelta.test\ngamma.test\nlocal.test\n');
      assert.equal(result.manifest.rulesets.domains.sources[0].count, 4);
      assert.match(result.manifest.rulesets.domains.output.sha256, /^[0-9a-f]{64}$/);
      const before = await snapshot(generated);
      const previousStat = await fs.stat(path.join(generated, 'manifest.json'));
      assert.equal((await run()).changed, false);
      assert.deepEqual(await snapshot(generated), before);
      assert.equal((await fs.stat(path.join(generated, 'manifest.json'))).mtimeMs, previousStat.mtimeMs);
      assert.equal((await run({ check: true })).changed, false);
    });
    await test('network concurrency is bounded while independent downloads make progress', async () => {
      for (const name of ['one', 'two', 'three']) responses.set('/' + name, { body: name + '.test\n', delay: 25 });
      config.rulesets.domains.sources.push(...['one', 'two', 'three'].map((name) => ({ url: origin + '/' + name, format: 'text' })));
      await saveConfig();
      peakRequests = 0;
      await run({ concurrency: 2 });
      assert.equal(peakRequests, 2);
      config.rulesets.domains.sources = [{ url: sourceURL, format: 'text' }];
      await saveConfig();
      await run({ allowShrink: true });
    });
    await test('stored-output checks detect stale override files', async () => {
      const override = path.join(root, 'Rules', 'overrides', 'domains.add.txt');
      const original = await fs.readFile(override);
      await fs.appendFile(override, 'pending.test\n');
      await assert.rejects(run({ check: true }), /override is out of date/);
      await fs.writeFile(override, original);
      await run({ check: true });
    });
    await test('a failed source retries at most three times and preserves every published file', async () => {
      const before = await snapshot(generated);
      const previousHits = hits.get('/domains');
      responses.set('/domains', { status: 503, body: 'unavailable' });
      await assert.rejects(run(), /HTTP status 503/);
      assert.equal(hits.get('/domains') - previousHits, 3);
      assert.deepEqual(await snapshot(generated), before);
      setDomains(defaultDomains);
    });
    await test('empty, HTML and illegal payloads never replace existing outputs', async () => {
      const before = await snapshot(generated);
      for (const body of ['', '# comments only\n', '<html>error</html>', 'good.test\nhttps://bad.test\n']) {
        setDomains(body);
        await assert.rejects(run());
        assert.deepEqual(await snapshot(generated), before);
      }
      setDomains(defaultDomains);
    });
    await test('unexpected source shrink is blocked before publication', async () => {
      const before = await snapshot(generated);
      setDomains('alpha.test\n');
      await assert.rejects(run(), /suspicious shrink/);
      assert.deepEqual(await snapshot(generated), before);
      setDomains(defaultDomains);
    });
    await test('explicit shrink approval changes the publication and remains verifiable', async () => {
      setDomains('alpha.test\n');
      assert.equal((await run({ allowShrink: true })).changed, true);
      await run({ check: true });
      setDomains(defaultDomains);
      await run();
    });
    await test('partial domain exclusion failure preserves outputs', async () => {
      const before = await snapshot(generated);
      setDomains('+.test\n');
      await assert.rejects(run({ allowShrink: true }), /routing exception/);
      assert.deepEqual(await snapshot(generated), before);
      setDomains(defaultDomains);
    });
    await test('redirects follow the explicit proxy route and excessive redirects fail safely', async () => {
      responses.set('/redirect', { status: 302, headers: { Location: '/domains' } });
      config.rulesets.domains.sources[0].url = origin + '/redirect';
      await saveConfig();
      const previousConnections = proxyConnections;
      await run({ proxy: proxyURL });
      assert(proxyConnections - previousConnections >= 3);
      const before = await snapshot(generated);
      responses.set('/loop', { status: 302, headers: { Location: '/loop' } });
      config.rulesets.domains.sources[0].url = origin + '/loop';
      await saveConfig();
      await assert.rejects(run(), /redirects/);
      assert.deepEqual(await snapshot(generated), before);
      config.rulesets.domains.sources[0].url = sourceURL;
      await saveConfig();
      await run();
    });
    await recipeTests(root, origin, responses);
    await test('all MRS compilation must succeed before publication; errors and empty outputs preserve old files', async () => {
      const compiler = path.join(root, 'fake-compiler.cjs');
      await fs.writeFile(compiler, "const fs=require('node:fs');const args=process.argv.slice(2);if(args[0]!=='convert-ruleset'||args[2]!=='text')process.exit(12);fs.writeFileSync(args[4],Buffer.concat([Buffer.from('MRS-fixture\\n'),fs.readFileSync(args[3])]));\n");
      const compile = (executable, args) => execFileAsync(executable, [compiler, ...args]);
      const result = await run({ mihomo: process.execPath, compile });
      assert(result.manifest.rulesets.domains.mrs);
      await run({ check: true });
      const before = await snapshot(generated);
      setDomains(defaultDomains + 'new.test\n');
      await fs.writeFile(compiler, "const fs=require('node:fs');const args=process.argv.slice(2);if(args[1]==='ipcidr')process.exit(23);fs.writeFileSync(args[4],'partial-compile');\n");
      await assert.rejects(run({ mihomo: process.execPath, compile }), /compilation failed/);
      assert.deepEqual(await snapshot(generated), before);
      await fs.writeFile(compiler, "require('node:fs').writeFileSync(process.argv.at(-1),'');\n");
      await assert.rejects(run({ mihomo: process.execPath, compile }), /empty MRS/);
      assert.deepEqual(await snapshot(generated), before);
      await assert.rejects(run(), /requires --mihomo/);
      assert.deepEqual(await snapshot(generated), before);
      setDomains(defaultDomains);
      await fs.writeFile(compiler, "const fs=require('node:fs');const args=process.argv.slice(2);fs.writeFileSync(args[4],Buffer.concat([Buffer.from('MRS-fixture\\n'),fs.readFileSync(args[3])]));\n");
      await run({ mihomo: process.execPath, compile });
      await new Promise((resolve) => server.close(resolve));
      const offline = await run({ offline: true, mihomo: process.execPath, compile });
      assert.equal(offline.changed, false);
    });
    await test('offline mode requires the exact URL and a verified cache checksum', async () => {
      const before = await snapshot(generated);
      config.rulesets.domains.sources[0].url = origin + '/uncached';
      await saveConfig();
      await assert.rejects(run({ offline: true }), /No verified cache/);
      config.rulesets.domains.sources[0].url = sourceURL;
      await saveConfig();
      const key = createHash('sha256').update(sourceURL).digest('hex');
      await fs.writeFile(path.join(root, '.cache', 'rule-sources', key + '.txt'), 'tampered.test\n');
      await assert.rejects(run({ offline: true }), /checksum mismatch/);
      assert.deepEqual(await snapshot(generated), before);
    });
    await test('stored-output validation catches corruption without network access', async () => {
      await fs.appendFile(path.join(generated, 'domain', 'domains.list'), 'injected.test\n');
      await assert.rejects(run({ check: true }), /checksum mismatch/);
      assert(!(await fs.readdir(path.join(root, 'Rules'))).some((name) => name.startsWith('.generated-') || name === '.update-rules.lock'));
    });
    await test('CLI reports invalid options as a failure without creating files', async () => {
      const script = path.resolve(__dirname, '..', 'Tools', 'update-rules.js');
      await assert.rejects(execFileAsync(process.execPath, [script, '--timeout', 'invalid']), /positive integer/);
      await assert.rejects(execFileAsync(process.execPath, [script, '--root', root, '--concurrency', '20']), /Concurrency/);
      const help = await execFileAsync(process.execPath, [script, '--help']);
      assert.match(help.stdout, /--offline/);
    });
  } finally {
    server.closeAllConnections();
    server.close();
    for (const socket of proxySockets) socket.destroy();
    await new Promise((resolve) => proxy.close(resolve));
    await fs.rm(root, { recursive: true, force: true });
  }
  console.log('\nPassed ' + checks + ' rule-maintenance checks.');
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
