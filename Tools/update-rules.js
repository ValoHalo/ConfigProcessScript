#!/usr/bin/env node
'use strict';

// Configuration: {version:1, rulesets:{id:{behavior:'domain'|'ipcidr',
// sources:[{url,format:'text'|'yaml'|'classical-text'}], add:[path], remove:[path], minEntries:1}}}
// Optional maxShrinkRatio defaults to 0.35. Paths are relative to the repository.
const fs = require('node:fs/promises');
const path = require('node:path');
const http = require('node:http');
const https = require('node:https');
const tls = require('node:tls');
const net = require('node:net');
const { domainToASCII } = require('node:url');
const { createHash, randomUUID } = require('node:crypto');
const { execFile } = require('node:child_process');
const { promisify, TextDecoder } = require('node:util');
const YAML = require('yaml');

const execFileAsync = promisify(execFile);
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const lexical = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
function normalizeDomain(value, literalDomains = []) {
  if (literalDomains.some((literal) => literal.toLowerCase() === value.toLowerCase())) return value.toLowerCase();
  const mode = value.startsWith('+.') ? '+.' : '';
  let domain = value.slice(mode.length);
  if (/[\s\\/:@?#%]/.test(domain)) throw new Error('Invalid domain entry: ' + value);
  if (domain.endsWith('.')) domain = domain.slice(0, -1);
  domain = domainToASCII(domain).toLowerCase();
  if (
    !domain ||
    domain.length > 253 ||
    !domain.split('.').every((label) => label === '*' || /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/.test(label))
  ) {
    throw new Error('Invalid domain entry: ' + value);
  }
  return mode + domain;
}

function domainParts(value) {
  const suffix = value.startsWith('+.');
  const domain = value.slice(suffix ? 2 : 0);
  return { suffix, domain, labels: domain.split('.') };
}

function coversDomain(outer, inner) {
  const a = domainParts(outer);
  const b = domainParts(inner);
  if (a.labels.length > b.labels.length || (!a.suffix && (b.suffix || a.labels.length !== b.labels.length))) return false;
  const offset = b.labels.length - a.labels.length;
  return a.labels.every((label, index) => label === '*' || label === b.labels[index + offset]);
}

function overlapsDomain(a, b) {
  const x = domainParts(a);
  const y = domainParts(b);
  if (!x.suffix && !y.suffix && x.labels.length !== y.labels.length) return false;
  if (x.suffix && !y.suffix && x.labels.length > y.labels.length) return false;
  if (y.suffix && !x.suffix && y.labels.length > x.labels.length) return false;
  for (let index = 1; index <= Math.min(x.labels.length, y.labels.length); index++) {
    const left = x.labels.at(-index);
    const right = y.labels.at(-index);
    if (left !== '*' && right !== '*' && left !== right) return false;
  }
  return true;
}

function deduplicateDomains(entries) {
  const unique = new Set(entries);
  const wildcards = [...unique].filter((entry) => entry.includes('*'));
  return [...unique]
    .filter((entry) => {
      const { domain } = domainParts(entry);
      const labels = domain.split('.');
      for (let index = 0; index < labels.length; index++) {
        const parent = '+.' + labels.slice(index).join('.');
        if (parent !== entry && unique.has(parent)) return false;
      }
      return !wildcards.some((wildcard) => wildcard !== entry && coversDomain(wildcard, entry));
    })
    .sort(lexical);
}

function parseIP(value) {
  const family = net.isIP(value);
  if (family === 4) {
    return { family, bits: 32, number: value.split('.').reduce((sum, part) => (sum << 8n) | BigInt(part), 0n) };
  }
  if (family !== 6 || value.includes('%')) throw new Error('Invalid IP address: ' + value);
  let address = value.toLowerCase();
  if (address.includes('.')) {
    const colon = address.lastIndexOf(':');
    const v4 = parseIP(address.slice(colon + 1)).number;
    address = address.slice(0, colon + 1) + (v4 >> 16n).toString(16) + ':' + (v4 & 65535n).toString(16);
  }
  const halves = address.split('::');
  let words;
  if (halves.length === 2) {
    const left = halves[0] ? halves[0].split(':') : [];
    const right = halves[1] ? halves[1].split(':') : [];
    words = [...left, ...Array(8 - left.length - right.length).fill('0'), ...right];
  } else words = address.split(':');
  return { family, bits: 128, number: words.reduce((sum, word) => (sum << 16n) | BigInt('0x' + word), 0n) };
}

function printIP(number, family) {
  if (family === 4) return [24n, 16n, 8n, 0n].map((shift) => Number((number >> shift) & 255n)).join('.');
  const words = Array.from({ length: 8 }, (_, index) => ((number >> BigInt((7 - index) * 16)) & 65535n).toString(16));
  let bestStart = -1;
  let bestLength = 1;
  for (let index = 0; index < words.length; index++) {
    if (words[index] !== '0') continue;
    let end = index;
    while (end < words.length && words[end] === '0') end++;
    if (end - index > bestLength) {
      bestStart = index;
      bestLength = end - index;
    }
    index = end - 1;
  }
  if (bestStart < 0) return words.join(':');
  return words.slice(0, bestStart).join(':') + '::' + words.slice(bestStart + bestLength).join(':');
}

function parseCIDR(value) {
  const parts = value.split('/');
  if (parts.length > 2 || (parts.length === 2 && !/^(0|[1-9][0-9]*)$/.test(parts[1]))) {
    throw new Error('Invalid CIDR entry: ' + value);
  }
  const ip = parseIP(parts[0]);
  const prefix = parts.length === 2 ? Number(parts[1]) : ip.bits;
  if (prefix < 0 || prefix > ip.bits) throw new Error('Invalid CIDR prefix: ' + value);
  const hostBits = BigInt(ip.bits - prefix);
  const start = (ip.number >> hostBits) << hostBits;
  const end = start + (1n << hostBits) - 1n;
  return { family: ip.family, prefix, start, end, text: printIP(start, ip.family) + '/' + prefix };
}

function deduplicateCIDRs(entries) {
  const ranges = [...new Set(entries)].map(parseCIDR).sort((a, b) => {
    return a.family - b.family || (a.start < b.start ? -1 : a.start > b.start ? 1 : a.prefix - b.prefix);
  });
  const kept = [];
  for (const range of ranges) {
    const last = kept.at(-1);
    if (last && last.family === range.family && last.start <= range.start && last.end >= range.end) continue;
    kept.push(range);
  }
  return kept.map((range) => range.text);
}

function parseEntries(body, format, behavior, label, allowEmpty = false, literalDomains = []) {
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(body).replace(/^\uFEFF/, '');
  } catch {
    throw new Error(label + ': content is not valid UTF-8');
  }
  if (/<(?:!doctype\s+html|html|head|body)(?:\s|>)/i.test(text)) throw new Error(label + ': received HTML');
  let values;
  if (format === 'yaml') {
    const document = YAML.parseDocument(text, { uniqueKeys: true });
    if (document.errors.length) throw new Error(label + ': invalid YAML: ' + document.errors[0].message);
    const data = document.toJS({ maxAliasCount: 100 });
    if (!data || !Array.isArray(data.payload)) throw new Error(label + ': YAML must contain a payload array');
    values = data.payload;
  } else values = text.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith('#'));
  if (format === 'classical-text') {
    if (behavior !== 'domain') throw new Error(label + ': classical-text only accepts domain rules');
    values = values.map((line) => {
      const parts = line.split(',').map((part) => part.trim());
      if (parts.length < 2 || parts.length > 3 || !['DOMAIN', 'DOMAIN-SUFFIX'].includes(parts[0]) || !parts[1]) {
        throw new Error(label + ': unsupported classical rule: ' + line);
      }
      return (parts[0] === 'DOMAIN-SUFFIX' ? '+.' : '') + parts[1];
    });
  }
  const entries = values.map((value, index) => {
    if (typeof value !== 'string' || !value.trim() || (/\s/.test(value.trim()) && !literalDomains.some((literal) => literal.toLowerCase() === value.trim().toLowerCase()))) {
      throw new Error(label + ': invalid entry ' + (index + 1));
    }
    try {
      return behavior === 'domain' ? normalizeDomain(value.trim(), literalDomains) : parseCIDR(value.trim()).text;
    } catch (error) {
      throw new Error(label + ': ' + error.message);
    }
  });
  if (!allowEmpty && !entries.length) throw new Error(label + ': empty rules are not accepted');
  return entries;
}

function mergeEntries(entries, removals, behavior) {
  if (behavior === 'domain') {
    const excluded = deduplicateDomains(removals);
    return deduplicateDomains(entries).filter((entry) => {
      if (excluded.some((removal) => coversDomain(removal, entry))) return false;
      const partial = excluded.find((removal) => overlapsDomain(entry, removal));
      if (partial) {
        throw new Error('Cannot subtract ' + partial + ' from covering rule ' + entry + '; use a routing exception before this ruleset');
      }
      return true;
    });
  }
  const excluded = deduplicateCIDRs(removals).map(parseCIDR);
  return deduplicateCIDRs(entries).filter((entry) => {
    const range = parseCIDR(entry);
    const relevant = excluded.filter((removal) => removal.family === range.family);
    if (relevant.some((removal) => removal.start <= range.start && removal.end >= range.end)) return false;
    const partial = relevant.find((removal) => removal.start <= range.end && removal.end >= range.start);
    if (partial) {
      throw new Error('Cannot subtract partial subnet ' + partial.text + ' from ' + entry + '; use a routing exception before this ruleset');
    }
    return true;
  });
}

async function requestOnce(url, options) {
  const target = new URL(url);
  if (!['http:', 'https:'].includes(target.protocol)) throw new Error('Only HTTP and HTTPS sources are allowed');
  let request;
  let socket;
  let agent;
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('Download timed out after ' + options.timeout + ' ms')), options.timeout);
  });
  try {
    if (options.proxy) {
      const proxy = new URL(options.proxy);
      if (proxy.protocol !== 'http:') throw new Error('--proxy must be an HTTP or mixed-port HTTP endpoint');
      const port = target.port || (target.protocol === 'https:' ? '443' : '80');
      socket = await Promise.race([
        new Promise((resolve, reject) => {
          const headers = { Host: target.host };
          if (proxy.username || proxy.password) {
            headers['Proxy-Authorization'] = 'Basic ' + Buffer.from(decodeURIComponent(proxy.username) + ':' + decodeURIComponent(proxy.password)).toString('base64');
          }
          request = http.request({ hostname: proxy.hostname, port: proxy.port || 80, method: 'CONNECT', path: target.hostname + ':' + port, headers, agent: false });
          request.once('connect', (response, connection, head) => {
            if (response.statusCode !== 200) {
              connection.destroy();
              reject(new Error('Proxy CONNECT status ' + response.statusCode));
              return;
            }
            if (head.length) connection.unshift(head);
            resolve(connection);
          });
          request.once('error', reject);
          request.end();
        }),
        timeout,
      ]);
      if (target.protocol === 'https:') {
        const hostname = target.hostname.replace(/^\[|\]$/g, '');
        socket = tls.connect({ socket, servername: net.isIP(hostname) ? undefined : hostname, rejectUnauthorized: true, checkServerIdentity: (_, certificate) => tls.checkServerIdentity(hostname, certificate), ALPNProtocols: ['http/1.1'] });
        await Promise.race([
          new Promise((resolve, reject) => {
            socket.once('secureConnect', resolve);
            socket.once('error', reject);
          }),
          timeout,
        ]);
      }
      agent = target.protocol === 'https:' ? new https.Agent({ keepAlive: false }) : new http.Agent({ keepAlive: false });
      agent.createConnection = () => socket;
    }
    return await Promise.race([
      new Promise((resolve, reject) => {
        const protocol = target.protocol === 'https:' ? https : http;
        request = protocol.request(target, { agent: agent || false, headers: { 'User-Agent': 'ConfigProcessScript-RuleUpdater/1.0', 'Accept-Encoding': 'identity', Connection: 'close' } }, (response) => {
          const chunks = [];
          let bytes = 0;
          response.on('data', (chunk) => {
            bytes += chunk.length;
            if (bytes > options.maxBytes) {
              reject(new Error('Source exceeds maximum download size'));
              response.destroy();
            } else chunks.push(chunk);
          });
          response.once('end', () => resolve({ status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks) }));
          response.once('error', reject);
          response.once('aborted', () => reject(new Error('Source response was interrupted')));
        });
        request.once('error', reject);
        request.end();
      }),
      timeout,
    ]);
  } finally {
    clearTimeout(timer);
    request?.destroy();
    agent?.destroy();
    socket?.destroy();
  }
}

async function download(url, options) {
  let lastError;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      let current = url;
      for (let redirects = 0; redirects <= 5; redirects++) {
        const response = await requestOnce(current, options);
        if ([301, 302, 303, 307, 308].includes(response.status)) {
          if (redirects === 5 || !response.headers.location) throw new Error('Invalid or excessive redirects');
          const next = new URL(response.headers.location, current);
          if (!['http:', 'https:'].includes(next.protocol) || next.username || next.password) throw new Error('Unsafe redirect URL');
          if (new URL(current).protocol === 'https:' && next.protocol !== 'https:') throw new Error('HTTPS downgrade redirect refused');
          current = next.href;
          continue;
        }
        if (response.status !== 200) throw new Error('HTTP status ' + response.status);
        if (/text\/html|application\/xhtml/i.test(response.headers['content-type'] || '')) throw new Error('Received HTML content type');
        if (response.headers['content-encoding'] && response.headers['content-encoding'] !== 'identity') throw new Error('Unexpected compressed response');
        return response.body;
      }
    } catch (error) {
      lastError = error;
    }
    if (attempt < 2) await new Promise((resolve) => setTimeout(resolve, 100 * (attempt + 1)));
  }
  throw new Error(url + ': ' + lastError.message);
}

async function mapLimit(values, limit, work) {
  const results = Array(values.length);
  let cursor = 0;
  let failure;
  await Promise.all(Array.from({ length: Math.min(limit, values.length) }, async () => {
    while (!failure) {
      const index = cursor++;
      if (index >= values.length) return;
      try { results[index] = await work(values[index]); } catch (error) { failure ||= error; }
    }
  }));
  if (failure) throw failure;
  return results;
}

function withinRoot(root, filename) {
  const resolved = path.resolve(root, filename);
  const relative = path.relative(root, resolved);
  if (!relative || relative.startsWith('..' + path.sep) || relative === '..' || path.isAbsolute(relative)) {
    throw new Error('Path must identify a file inside the repository: ' + filename);
  }
  return resolved;
}

function validateConfig(config) {
  if (config.version !== 1 || !config.rulesets || typeof config.rulesets !== 'object' || Array.isArray(config.rulesets)) {
    throw new Error('Expected version: 1 and a rulesets object');
  }
  const entries = Object.entries(config.rulesets).sort(([a], [b]) => lexical(a, b));
  if (!entries.length) throw new Error('No rulesets configured');
  if (new Set(entries.map(([id]) => id.toLowerCase())).size !== entries.length) throw new Error('Ruleset IDs must be unique ignoring case');
  for (const [id, rule] of entries) {
    if (!/^[a-z0-9][a-z0-9._!@-]*$/i.test(id) || id.endsWith('.') || /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(id)) throw new Error('Invalid ruleset ID: ' + id);
    if (!rule || !['domain', 'ipcidr'].includes(rule.behavior)) throw new Error(id + ': behavior must be domain or ipcidr');
    if (!Array.isArray(rule.sources) || !rule.sources.every((source) => source && ['text', 'yaml', 'classical-text'].includes(source.format))) throw new Error(id + ': invalid sources');
    if (!Number.isInteger(rule.minEntries) || rule.minEntries < 1) throw new Error(id + ': minEntries must be a positive integer');
    if (rule.maxShrinkRatio !== undefined && (typeof rule.maxShrinkRatio !== 'number' || !(rule.maxShrinkRatio >= 0) || !(rule.maxShrinkRatio <= 1))) throw new Error(id + ': invalid maxShrinkRatio');
    for (const source of rule.sources) {
      const url = new URL(source.url);
      if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash) throw new Error(id + ': unsafe source URL');
      if (source.allowLiteralDomains !== undefined && (!Array.isArray(source.allowLiteralDomains) || rule.behavior !== 'domain' || !source.allowLiteralDomains.every((literal) => typeof literal === 'string' && literal.length > 0 && literal.length <= 253 && literal === literal.trim() && !/[\x00-\x1f\x7f\\/:@?#%,]/.test(literal)))) throw new Error(id + ': invalid allowLiteralDomains whitelist');
    }
    for (const key of ['add', 'remove']) {
      if (rule[key] !== undefined && (!Array.isArray(rule[key]) || !rule[key].every((filename) => typeof filename === 'string' && filename))) throw new Error(id + ': ' + key + ' must be an array of paths');
    }
  }
  return entries;
}

async function readJSON(filename, optional = false) {
  try { return JSON.parse(await fs.readFile(filename, 'utf8')); } catch (error) {
    if (optional && error.code === 'ENOENT') return null;
    throw error;
  }
}

async function loadSource(source, behavior, options) {
  const key = sha256(source.url);
  const bodyPath = path.join(options.cache, key + '.txt');
  const metaPath = path.join(options.cache, key + '.json');
  let body;
  if (options.offline) {
    const meta = await readJSON(metaPath, true);
    if (!meta || meta.url !== source.url) throw new Error('No verified cache for ' + source.url);
    body = await fs.readFile(bodyPath);
    if (meta.sha256 !== sha256(body)) throw new Error('Cached source checksum mismatch: ' + source.url);
  } else body = await download(source.url, options);
  const entries = parseEntries(body, source.format, behavior, source.url, false, source.allowLiteralDomains);
  const hash = sha256(body);
  if (!options.offline) {
    await fs.writeFile(bodyPath, body);
    await fs.writeFile(metaPath, JSON.stringify({ version: 1, url: source.url, sha256: hash }, null, 2) + '\n');
  }
  return { entries, record: { url: source.url, format: source.format, ...(source.allowLiteralDomains ? { allowLiteralDomains: source.allowLiteralDomains } : {}), sha256: hash, count: entries.length } };
}

async function checkGenerated(root, config) {
  const generated = path.join(root, 'Rules', 'generated');
  const manifest = await readJSON(path.join(generated, 'manifest.json'));
  const rules = validateConfig(config);
  if (manifest.version !== 1 || !manifest.rulesets) throw new Error('Invalid generated manifest');
  if (Object.keys(manifest.rulesets).sort().join('\n') !== rules.map(([id]) => id).join('\n')) throw new Error('Generated rulesets do not match configuration');
  for (const [id, rule] of rules) {
    const record = manifest.rulesets[id];
    const filename = rule.behavior + '/' + id + '.list';
    if (record.behavior !== rule.behavior || record.output.path !== filename) throw new Error(id + ': generated behavior/path mismatch');
    const describeSource = (source) => ({ url: source.url, format: source.format, ...(source.allowLiteralDomains ? { allowLiteralDomains: source.allowLiteralDomains } : {}) });
    if (JSON.stringify(record.sources.map(describeSource)) !== JSON.stringify(rule.sources.map(describeSource))) throw new Error(id + ': generated source configuration is out of date');
    for (const key of ['add', 'remove']) {
      const filenames = rule[key] || [];
      if (record[key].length !== filenames.length) throw new Error(id + ': generated ' + key + ' configuration is out of date');
      for (let index = 0; index < filenames.length; index++) {
        const override = record[key][index];
        if (override.path !== filenames[index].replaceAll('\\', '/') || override.sha256 !== sha256(await fs.readFile(withinRoot(root, filenames[index])))) throw new Error(id + ': generated override is out of date: ' + filenames[index]);
      }
    }
    const body = await fs.readFile(withinRoot(generated, filename));
    if (sha256(body) !== record.output.sha256) throw new Error(id + ': generated list checksum mismatch');
    const entries = parseEntries(body, 'text', rule.behavior, filename, false, rule.sources.flatMap((source) => source.allowLiteralDomains || []));
    if (record.count !== entries.length || entries.length < rule.minEntries) throw new Error(id + ': generated entry count mismatch');
    const normalized = mergeEntries(entries, [], rule.behavior).join('\n') + '\n';
    if (normalized !== body.toString('utf8')) throw new Error(id + ': generated list is not normalized');
    if (record.mrs) {
      if (record.mrs.path !== rule.behavior + '/' + id + '.mrs') throw new Error(id + ': invalid MRS path');
      const mrs = await fs.readFile(withinRoot(generated, record.mrs.path));
      if (!mrs.length || sha256(mrs) !== record.mrs.sha256) throw new Error(id + ': MRS checksum mismatch');
    }
  }
  return manifest;
}

async function updateRules(input = {}) {
  const root = path.resolve(input.root || path.join(__dirname, '..'));
  const options = { timeout: 30000, maxBytes: 32 * 1024 * 1024, concurrency: 4, ...input, root };
  options.cache = path.resolve(root, input.cache || '.cache/rule-sources');
  const configPath = path.resolve(root, input.config || 'config/rule-sources.json');
  const config = await readJSON(configPath);
  const rules = validateConfig(config);
  if (!Number.isInteger(options.concurrency) || options.concurrency < 1 || options.concurrency > 16) throw new Error('Concurrency must be 1..16');
  if (options.check) return { changed: false, manifest: await checkGenerated(root, config) };
  const rulesDirectory = path.join(root, 'Rules');
  const destination = path.join(rulesDirectory, 'generated');
  const stage = path.join(rulesDirectory, '.generated-stage-' + randomUUID());
  const backup = path.join(rulesDirectory, '.generated-backup-' + randomUUID());
  await fs.mkdir(options.cache, { recursive: true });
  await fs.mkdir(rulesDirectory, { recursive: true });
  const lockPath = path.join(rulesDirectory, '.update-rules.lock');
  let lock;
  try { lock = await fs.open(lockPath, 'wx'); } catch (error) {
    if (error.code === 'EEXIST') throw new Error('Another rule update is running, or a stale Rules/.update-rules.lock needs inspection');
    throw error;
  }
  let backedUp = false;
  let published = false;
  try {
    await lock.writeFile(String(process.pid) + '\n');
    const oldManifest = await readJSON(path.join(destination, 'manifest.json'), true);
    const manifest = { version: 1, rulesets: {} };
    const sourceJobs = new Map();
    for (const [, rule] of rules) {
      for (const source of rule.sources) {
        const key = JSON.stringify([source, rule.behavior]);
        sourceJobs.set(key, { key, source, behavior: rule.behavior });
      }
    }
    const loaded = await mapLimit([...sourceJobs.values()], options.concurrency, async (job) => {
      return [job.key, await loadSource(job.source, job.behavior, options)];
    });
    const sources = new Map(loaded);
    await fs.mkdir(stage, { recursive: true });
    for (const [id, rule] of rules) {
      const records = rule.sources.map((source) => sources.get(JSON.stringify([source, rule.behavior])));
      const maxShrink = rule.maxShrinkRatio ?? 0.35;
      if (!options.allowShrink) {
        for (const source of records) {
          const previousSource = oldManifest?.rulesets?.[id]?.sources?.find((previous) => previous.url === source.record.url && previous.format === source.record.format);
          if (previousSource?.count && source.record.count < previousSource.count * (1 - maxShrink)) {
            throw new Error(id + ': suspicious shrink in source from ' + previousSource.count + ' to ' + source.record.count + ' rules; inspect changes and use --allow-shrink only when intended');
          }
        }
      }
      const additions = [];
      const removals = [];
      const addEntries = [];
      const removeEntries = [];
      for (const [key, target, entries] of [['add', additions, addEntries], ['remove', removals, removeEntries]]) {
        for (const filename of rule[key] || []) {
          const body = await fs.readFile(withinRoot(root, filename));
          const parsed = parseEntries(body, 'text', rule.behavior, filename, true);
          entries.push(...parsed);
          target.push({ path: filename.replaceAll('\\', '/'), sha256: sha256(body), count: parsed.length });
        }
      }
      const entries = mergeEntries([...records.flatMap((record) => record.entries), ...addEntries], removeEntries, rule.behavior);
      if (entries.length < rule.minEntries) throw new Error(id + ': only ' + entries.length + ' rules, below minEntries ' + rule.minEntries);
      const previous = oldManifest?.rulesets?.[id]?.count;
      if (!options.allowShrink && previous && entries.length < previous * (1 - maxShrink)) {
        throw new Error(id + ': suspicious shrink from ' + previous + ' to ' + entries.length + ' rules; inspect changes and use --allow-shrink only when intended');
      }
      const outputPath = rule.behavior + '/' + id + '.list';
      const output = entries.join('\n') + '\n';
      const filename = path.join(stage, outputPath);
      await fs.mkdir(path.dirname(filename), { recursive: true });
      await fs.writeFile(filename, output);
      const record = { behavior: rule.behavior, count: entries.length, sources: records.map((source) => source.record), add: additions, remove: removals, output: { path: outputPath, sha256: sha256(output) } };
      if (options.mihomo) {
        const mrsPath = rule.behavior + '/' + id + '.mrs';
        const mrsFilename = path.join(stage, mrsPath);
        const args = ['convert-ruleset', rule.behavior, 'text', filename, mrsFilename];
        try {
          await (options.compile || ((executable, parameters) => execFileAsync(executable, parameters, { windowsHide: true, timeout: 120000, maxBuffer: 1024 * 1024 })))(options.mihomo, args);
        } catch (error) {
          throw new Error(id + ': MRS compilation failed: ' + error.message);
        }
        const body = await fs.readFile(mrsFilename);
        if (!body.length) throw new Error(id + ': compiler produced an empty MRS file');
        record.mrs = { path: mrsPath, sha256: sha256(body) };
      } else if (oldManifest?.rulesets?.[id]?.mrs) {
        throw new Error(id + ': existing MRS publication requires --mihomo; refusing to remove compiled rules');
      }
      manifest.rulesets[id] = record;
    }
    const serialized = JSON.stringify(manifest, null, 2) + '\n';
    await fs.writeFile(path.join(stage, 'manifest.json'), serialized);
    if (oldManifest && JSON.stringify(oldManifest) === JSON.stringify(manifest)) {
      await checkGenerated(root, config);
      return { changed: false, manifest };
    }
    try { await fs.rename(destination, backup); backedUp = true; } catch (error) { if (error.code !== 'ENOENT') throw error; }
    await fs.rename(stage, destination);
    published = true;
    return { changed: true, manifest };
  } finally {
    if (backedUp && !published) await fs.rename(backup, destination);
    await fs.rm(stage, { recursive: true, force: true });
    if (published && backedUp) await fs.rm(backup, { recursive: true, force: true });
    await lock.close();
    await fs.rm(lockPath, { force: true });
  }
}

async function main(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (arg === '--offline') options.offline = true;
    else if (arg === '--allow-shrink') options.allowShrink = true;
    else if (arg === '--check') options.check = true;
    else if (['--root', '--config', '--cache', '--mihomo', '--proxy', '--timeout', '--concurrency'].includes(arg)) {
      const value = argv[++index];
      if (!value || value.startsWith('--')) throw new Error(arg + ' requires a value');
      options[arg.slice(2)] = ['--timeout', '--concurrency'].includes(arg) ? Number(value) : value;
    } else if (arg === '--help' || arg === '-h') {
      console.log('node Tools/update-rules.js [--root path] [--config config/rule-sources.json] [--mihomo executable] [--proxy http://127.0.0.1:port] [--offline] [--check] [--allow-shrink] [--timeout 30000] [--concurrency 4]');
      return;
    } else throw new Error('Unknown option: ' + arg);
  }
  if (options.timeout !== undefined && (!Number.isInteger(options.timeout) || options.timeout < 1)) throw new Error('--timeout must be a positive integer');
  const result = await updateRules(options);
  console.log((options.check ? 'Verified' : result.changed ? 'Updated' : 'Unchanged') + ': ' + Object.keys(result.manifest.rulesets).length + ' rulesets, ' + Object.values(result.manifest.rulesets).reduce((sum, rule) => sum + rule.count, 0) + ' entries');
}

if (require.main === module) main(process.argv.slice(2)).catch((error) => { console.error(error.message); process.exitCode = 1; });
module.exports = { updateRules, checkGenerated, normalizeDomain, parseCIDR, parseEntries, mergeEntries, coversDomain, download };
