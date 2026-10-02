'use strict';
const http = require('node:http');
const net = require('node:net');
const dgram = require('node:dgram');
const { once } = require('node:events');
const { Transform } = require('node:stream');

async function listen(server, port = 0) {
  server.listen(port, '127.0.0.1');
  await once(server, 'listening');
  const sockets = new Set();
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });
  return {
    server,
    port: server.address().port,
    closeConnections: () => { for (const socket of sockets) socket.destroy(); },
    close: () =>
      new Promise((resolve) => {
        for (const s of sockets) s.destroy();
        server.close(resolve);
      }),
  };
}
async function freePort() {
  // A mixed proxy also binds UDP; some Windows ports are reserved only for UDP.
  for (let attempt = 0; attempt < 20; attempt++) {
    // Binding TCP port 0 can repeatedly choose from the same UDP-excluded
    // ephemeral range. Probe a fresh random candidate for both protocols.
    let listener;
    try { listener = await listen(net.createServer(), 10240 + Math.floor(Math.random() * 40000)); }
    catch (error) {
      if (['EACCES', 'EADDRINUSE'].includes(error.code)) continue;
      throw error;
    }
    const udp = dgram.createSocket('udp4');
    try {
      await new Promise((resolve, reject) => {
        udp.once('error', reject);
        udp.bind(listener.port, '127.0.0.1', resolve);
      });
      return listener.port;
    } catch (error) {
      if (!['EACCES', 'EADDRINUSE'].includes(error.code)) throw error;
    } finally {
      try { udp.close(); } catch {}
      await listener.close();
    }
  }
  throw new Error('No free TCP/UDP test port found');
}
function dnsAnswer(query, address = '203.0.113.7') {
  let end = 12;
  while (query[end]) end += query[end] + 1;
  end += 5;
  const question = query.subarray(12, end);
  const header = Buffer.from(query.subarray(0, 12));
  header.writeUInt16BE(0x8180, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(0, 8);
  header.writeUInt16BE(0, 10);
  const type = query.readUInt16BE(end - 4);
  header.writeUInt16BE(type === 1 ? 1 : 0, 6);
  if (type !== 1) return Buffer.concat([header, question]);
  const record = Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, ...address.split('.').map(Number)]);
  return Buffer.concat([header, question, record]);
}
function dnsQuestion(query) {
  const labels = [];
  for (let i = 12; query[i]; ) {
    const size = query[i++];
    labels.push(query.subarray(i, i + size).toString());
    i += size;
  }
  return labels.join('.');
}
// Read EDNS Client Subnet from the actual DNS wire query, not URL settings.
function dnsClientSubnets(query) {
  const skipName = (start) => {
    let offset = start;
    while (query[offset]) {
      if ((query[offset] & 0xc0) === 0xc0) return offset + 2;
      offset += query[offset] + 1;
      if (offset >= query.length) throw new Error('Malformed DNS name');
    }
    return offset + 1;
  };
  let offset = 12;
  for (let count = query.readUInt16BE(4); count; count--) offset = skipName(offset) + 4;
  const result = [];
  for (const position of [6, 8, 10]) {
    for (let count = query.readUInt16BE(position); count; count--) {
      offset = skipName(offset);
      const type = query.readUInt16BE(offset), size = query.readUInt16BE(offset + 8);
      offset += 10;
      const end = offset + size;
      if (type === 41) {
        while (offset < end) {
          const code = query.readUInt16BE(offset), length = query.readUInt16BE(offset + 2);
          offset += 4;
          if (code === 8) {
            const family = query.readUInt16BE(offset), prefix = query[offset + 2], scope = query[offset + 3];
            const bytes = [...query.subarray(offset + 4, offset + length)];
            const address = family === 1 ? [...bytes, ...Array(4 - bytes.length).fill(0)].join('.') : Buffer.from(bytes).toString('hex');
            result.push({ family, prefix, scope, address });
          }
          offset += length;
        }
      }
      offset = end;
    }
  }
  return result;
}
async function fixtures(options = {}) {
  const seen = [];
  const states = new Map();
  const origin = await listen(
    http.createServer(async (req, res) => {
      const route = req.headers['x-test-route'] || 'DIRECT';
      if (req.url.startsWith('/dns-query')) {
        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        const query =
          req.method === 'GET'
            ? Buffer.from(new URL(req.url, 'http://localhost').searchParams.get('dns'), 'base64url')
            : Buffer.concat(chunks);
        const name = dnsQuestion(query);
        const endpoint = new URL(req.url, 'http://localhost');
        const resolver = endpoint.searchParams.get('resolver') || decodeURIComponent(endpoint.pathname.split('/')[2] || '');
        seen.push({ kind: 'dns', route, name, resolver, ecs: dnsClientSubnets(query) });
        const status = options.dnsStatus?.({ name, resolver, route }) || 200;
        if (status !== 200) { res.writeHead(status); res.end(); return; }
        res.writeHead(200, { 'Content-Type': 'application/dns-message' });
        const address = typeof options.dnsAddress === 'function' ? options.dnsAddress(name) : options.dnsAddress;
        res.end(dnsAnswer(query, address || '203.0.113.7'));
        return;
      }
      if (req.url.startsWith('/health')) {
        const state = states.get(route);
        seen.push({ kind: 'health', route, url: req.url, time: Date.now() });
        res.on('finish', () => seen.push({ kind: 'health-complete', route, url: req.url, time: Date.now() }));
        if (state?.healthTimeout) return;
        if (req.url.startsWith('/health-auto')) {
          if (state?.autoDelay) await new Promise((resolve) => setTimeout(resolve, state.autoDelay));
          res.writeHead(state?.autoStatus ?? 204);
          res.end();
        } else {
          res.writeHead(state?.healthStatus ?? 200);
          res.end('health');
        }
        return;
      }
      seen.push({ kind: 'http', route, host: req.headers.host, url: req.url });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      if (req.url.startsWith('/hold')) {
        res.write(JSON.stringify({ route }) + '\n');
        const timer = setInterval(() => res.write(JSON.stringify({ route }) + '\n'), 100);
        res.on('close', () => clearInterval(timer));
        return;
      }
      res.end(JSON.stringify({ route }));
    }),
  );
  const proxies = [];
  for (const name of ['US 01', 'US 02', 'JP 01', 'HK 01']) {
    const state = { online: true, healthStatus: 200 };
    states.set(name, state);
    const proxy = http.createServer((req, res) => {
      res.writeHead(400);
      res.end();
    });
    proxy.on('connect', (req, client, head) => {
      seen.push({ kind: 'connect', route: name, target: req.url });
      if (!state.online) {
        client.end('HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n');
        return;
      }
      const port = Number(req.url.slice(req.url.lastIndexOf(':') + 1));
      if (port !== origin.port) {
        client.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n');
        return;
      }
      const upstream = net.connect({ host: '127.0.0.1', port });
      upstream.on('error', () => client.destroy());
      client.on('error', () => upstream.destroy());
      client.on('close', () => upstream.destroy());
      upstream.on('close', () => client.destroy());
      upstream.on('connect', () => {
        client.write('HTTP/1.1 200 Connection established\r\n\r\n');
        let buffer = Buffer.alloc(0),
          bodyRemaining = 0;
        const tagger = new Transform({
          transform(chunk, encoding, done) {
            buffer = Buffer.concat([buffer, chunk]);
            while (buffer.length) {
              if (bodyRemaining) {
                const size = Math.min(bodyRemaining, buffer.length);
                this.push(buffer.subarray(0, size));
                buffer = buffer.subarray(size);
                bodyRemaining -= size;
                if (bodyRemaining) break;
                continue;
              }
              const end = buffer.indexOf('\r\n\r\n');
              if (end < 0) break;
              const headers = buffer.subarray(0, end).toString();
              const length = /\r\nContent-Length:\s*(\d+)/i.exec(headers);
              bodyRemaining = length ? Number(length[1]) : 0;
              this.push(Buffer.from(headers + '\r\nX-Test-Route: ' + name + '\r\n\r\n'));
              buffer = buffer.subarray(end + 4);
            }
            done();
          },
        });
        client.pipe(tagger).pipe(upstream);
        if (head.length) tagger.write(head);
        upstream.pipe(client);
      });
    });
    const listener = await listen(proxy);
    proxies.push({ name, ...listener });
  }
  const udp = dgram.createSocket('udp4');
  udp.on('message', (query, remote) => {
    seen.push({ kind: 'dns', route: 'DIRECT-UDP', name: dnsQuestion(query) });
    udp.send(dnsAnswer(query, '127.0.0.1'), remote.port, remote.address);
  });
  udp.bind(0, '127.0.0.1');
  await once(udp, 'listening');
  return {
    origin,
    proxies,
    states,
    seen,
    udpPort: udp.address().port,
    subscription: () => ({
      proxies: proxies.map(({ name, port }) => ({ name, type: 'http', server: '127.0.0.1', port })),
    }),
    close: async () => {
      await Promise.all(proxies.map((p) => p.close()));
      await origin.close();
      await new Promise((resolve) => udp.close(resolve));
    },
  };
}
function request({ proxyPort, url, headers = {}, timeout = 5000 }) {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port: proxyPort,
        method: 'GET',
        path: url,
        headers: { Host: target.host, ...headers },
        agent: false,
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }));
        res.on('error', reject);
      },
    );
    req.on('error', reject);
    req.setTimeout(timeout, () => req.destroy(new Error('Request timeout')));
    req.end();
  });
}
module.exports = { fixtures, freePort, request, dnsAnswer, dnsClientSubnets };
