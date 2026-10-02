#!/usr/bin/env node
'use strict';
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const tls = require('node:tls');
const { performance } = require('node:perf_hooks');

/** One request over an explicit route. Never inherits HTTP_PROXY or the system proxy. */
async function probe({
  url,
  proxy,
  direct = false,
  timeout = 10000,
  maxBytes = 262144,
  method = 'GET',
  headers = {},
  body,
  includeBody = false,
}) {
  const target = new URL(url);
  if (!['http:', 'https:'].includes(target.protocol)) throw new Error('Only HTTP and HTTPS targets are supported');
  if (Boolean(proxy) === Boolean(direct)) throw new Error('Choose exactly one route: proxy or direct');
  const started = performance.now();
  const port = Number(target.port || (target.protocol === 'https:' ? 443 : 80));
  let socket, agent, request, timer;
  const timings = {};
  let expire;
  const expired = new Promise((_, reject) => {
    expire = () => reject(new Error('Probe timed out'));
    timer = setTimeout(expire, timeout);
  });
  try {
    const connected = new Promise((resolve, reject) => {
      if (direct) {
        socket = net.connect({ host: target.hostname, port });
        socket.once('connect', () => resolve(socket));
        socket.once('error', reject);
      } else {
        const endpoint = new URL(proxy);
        if (endpoint.protocol !== 'http:') {
          reject(new Error('The proxy must be an HTTP or mixed-port HTTP endpoint'));
          return;
        }
        const proxyHeaders = { Host: target.host };
        if (endpoint.username || endpoint.password)
          proxyHeaders['Proxy-Authorization'] =
            'Basic ' +
            Buffer.from(decodeURIComponent(endpoint.username) + ':' + decodeURIComponent(endpoint.password)).toString(
              'base64',
            );
        request = http.request({
          hostname: endpoint.hostname,
          port: endpoint.port || 80,
          method: 'CONNECT',
          path: target.hostname + ':' + port,
          headers: proxyHeaders,
          agent: false,
        });
        request.once('connect', (res, connection, head) => {
          socket = connection;
          if (res.statusCode !== 200) {
            connection.destroy();
            reject(new Error('Proxy CONNECT status ' + res.statusCode));
            return;
          }
          if (head.length) connection.unshift(head);
          resolve(connection);
        });
        request.once('error', reject);
        request.end();
      }
    });
    await Promise.race([connected, expired]);
    timings.connectMs = performance.now() - started;
    if (target.protocol === 'https:') {
      const tlsStarted = performance.now();
      socket = tls.connect({
        socket,
        servername: net.isIP(target.hostname) ? undefined : target.hostname,
        rejectUnauthorized: true,
        ALPNProtocols: ['http/1.1'],
      });
      await Promise.race([
        new Promise((resolve, reject) => {
          socket.once('secureConnect', resolve);
          socket.once('error', reject);
        }),
        expired,
      ]);
      timings.tlsMs = performance.now() - tlsStarted;
    }
    const result = await Promise.race([
      new Promise((resolve, reject) => {
        const protocol = target.protocol === 'https:' ? https : http;
        agent = new protocol.Agent({ keepAlive: false });
        agent.createConnection = () => socket;
        request = protocol.request(
          {
            hostname: target.hostname,
            port,
            path: target.pathname + target.search,
            method,
            agent,
            headers: {
              'User-Agent': 'ClashConfigProcesser-Probe/1.0',
              Connection: 'close',
              ...headers,
              ...(body ? { 'Content-Length': Buffer.byteLength(body) } : {}),
            },
          },
          (res) => {
            timings.firstByteMs = performance.now() - started;
            const chunks = [];
            let bytes = 0,
              truncated = false,
              ended = false;
            function finish() {
              if (ended) return;
              ended = true;
              timings.totalMs = performance.now() - started;
              const response = {
                status: res.statusCode,
                bytes,
                truncated,
                timings: Object.fromEntries(Object.entries(timings).map(([k, v]) => [k, Math.round(v * 100) / 100])),
              };
              if (includeBody) response.body = Buffer.concat(chunks);
              resolve(response);
            }
            res.on('data', (chunk) => {
              const accepted = chunk.subarray(0, Math.max(0, maxBytes - bytes));
              bytes += accepted.length;
              if (includeBody) chunks.push(accepted);
              if (accepted.length < chunk.length || bytes >= maxBytes) {
                truncated = true;
                finish();
                res.destroy();
              }
            });
            res.once('end', finish);
            res.once('error', (error) => {
              if (!ended) reject(error);
            });
          },
        );
        request.once('error', reject);
        request.end(body);
      }),
      expired,
    ]);
    return result;
  } finally {
    clearTimeout(timer);
    request?.destroy();
    agent?.destroy();
    socket?.destroy();
  }
}

async function main(argv) {
  const options = { count: 3, timeout: 10000, expectedStatus: null };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--direct') options.direct = true;
    else if (['--url', '--proxy', '--count', '--timeout', '--expect-status'].includes(arg)) {
      const value = argv[++i];
      if (!value) throw new Error(arg + ' requires a value');
      const key = { '--expect-status': 'expectedStatus' }[arg] || arg.slice(2);
      options[key] = ['count', 'timeout', 'expectedStatus'].includes(key) ? Number(value) : value;
    } else if (arg === '--help' || arg === '-h') {
      console.log(
        'node Tools/probe-proxy.js --url <https://...> (--proxy <http://127.0.0.1:port> | --direct) [--count 3] [--timeout 10000] [--expect-status 200]',
      );
      return;
    } else throw new Error('Unknown option: ' + arg);
  }
  if (
    options.expectedStatus !== null &&
    (!Number.isInteger(options.expectedStatus) || options.expectedStatus < 100 || options.expectedStatus > 599)
  )
    throw new Error('Expected status must be an HTTP status code');
  if (
    !options.url ||
    !Number.isInteger(options.count) ||
    options.count < 1 ||
    options.count > 10 ||
    !Number.isInteger(options.timeout) ||
    options.timeout < 100 ||
    options.timeout > 60000
  )
    throw new Error('URL, count (1-10), and timeout (100-60000 ms) are required');
  const target = new URL(options.url);
  const results = [];
  for (let i = 0; i < options.count; i++) {
    try {
      const result = await probe(options);
      result.expectedStatusMatched = options.expectedStatus === null ? null : result.status === options.expectedStatus;
      results.push(result);
    } catch (error) {
      results.push({ error: error.message });
    }
  }
  console.log(
    JSON.stringify(
      { target: target.origin + target.pathname, route: options.direct ? 'direct' : 'explicit-proxy', results },
      null,
      2,
    ),
  );
  if (results.some((r) => r.error || r.expectedStatusMatched === false)) process.exitCode = 1;
}
if (require.main === module)
  main(process.argv.slice(2)).catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
module.exports = { probe };
