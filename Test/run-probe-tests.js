'use strict';
const assert = require('node:assert/strict');
const { fixtures } = require('./lib/network-fixtures');
const { probe } = require('../Tools/probe-proxy');

async function main() {
  const fx = await fixtures();
  let passed = 0;
  async function test(name, fn) {
    await fn();
    passed++;
    console.log('PASS ' + name);
  }
  const target = 'http://app-fixture.example.net:' + fx.origin.port + '/route';
  try {
    await test('Probe requires an explicit route before connecting', async () => {
      await assert.rejects(probe({ url: target }), /exactly one route/);
      await assert.rejects(probe({ url: target, direct: true, proxy: 'http://127.0.0.1:1' }), /exactly one route/);
    });
    await test('Explicit proxy ignores ambient proxy variables', async () => {
      const saved = process.env.HTTP_PROXY;
      process.env.HTTP_PROXY = 'http://127.0.0.1:1';
      try {
        const response = await probe({
          url: target,
          proxy: 'http://127.0.0.1:' + fx.proxies[0].port,
          includeBody: true,
        });
        assert.equal(response.status, 200);
        assert.equal(JSON.parse(response.body).route, 'US 01');
        assert(response.timings.totalMs >= response.timings.firstByteMs);
      } finally {
        if (saved === undefined) delete process.env.HTTP_PROXY;
        else process.env.HTTP_PROXY = saved;
      }
    });
    await test('Direct probe reaches origin without a proxy', async () => {
      const response = await probe({
        url: 'http://127.0.0.1:' + fx.origin.port + '/route',
        direct: true,
        includeBody: true,
      });
      assert.equal(JSON.parse(response.body).route, 'DIRECT');
    });
    await test('HTTP error status is reported without treating it as success', async () => {
      fx.states.get('US 01').healthStatus = 503;
      const response = await probe({
        url: 'http://health.example.net:' + fx.origin.port + '/health',
        proxy: 'http://127.0.0.1:' + fx.proxies[0].port,
      });
      assert.equal(response.status, 503);
    });
    await test('Response limit closes the stream and marks truncation', async () => {
      const response = await probe({
        url: target,
        proxy: 'http://127.0.0.1:' + fx.proxies[0].port,
        maxBytes: 4,
        includeBody: true,
      });
      assert.equal(response.bytes, 4);
      assert.equal(response.body.length, 4);
      assert.equal(response.truncated, true);
    });
    await test('Failed CONNECT propagates the failure', async () => {
      fx.states.get('US 01').online = false;
      await assert.rejects(
        probe({ url: target, proxy: 'http://127.0.0.1:' + fx.proxies[0].port }),
        /CONNECT status 502/,
      );
    });
  } finally {
    await fx.close();
  }
  console.log('Probe checks: ' + passed + ' passed');
}
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
