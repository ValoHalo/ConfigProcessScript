'use strict';
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const crypto = require('node:crypto');

function cleanProxyEnvironment() {
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (/^(https?_proxy|all_proxy|no_proxy|node_use_env_proxy|node_options)$/i.test(key)) delete env[key];
  }
  return env;
}

class BettboxCore {
  constructor(binary, directory) {
    this.binary = binary;
    this.directory = path.resolve(directory);
    this.pending = new Map();
    this.logs = '';
    this.nextId = 1;
  }
  async start() {
    fs.mkdirSync(this.directory, { recursive: true });
    this.server = net.createServer();
    this.server.listen(0, '127.0.0.1');
    await once(this.server, 'listening');
    const connected = once(this.server, 'connection');
    this.process = spawn(this.binary, [String(this.server.address().port)], {
      cwd: this.directory,
      env: cleanProxyEnvironment(),
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    for (const stream of [this.process.stdout, this.process.stderr])
      stream.on('data', (data) => {
        this.logs = (this.logs + data).slice(-30000);
      });
    const exit = once(this.process, 'exit').then(([code]) => {
      throw new Error('BettboxCore exited before IPC connection: ' + code + '\n' + this.logs);
    });
    let timer;
    try {
      [this.socket] = await Promise.race([
        connected,
        exit,
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error('BettboxCore IPC connection timed out\n' + this.logs)), 8000);
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
    this.server.close();
    let buffer = Buffer.alloc(0);
    this.socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      while (buffer.length >= 4) {
        const size = buffer.readUInt32LE();
        if (size > 10 * 1024 * 1024) {
          this.socket.destroy(new Error('Invalid IPC frame size'));
          return;
        }
        if (buffer.length < size + 4) return;
        const message = JSON.parse(buffer.subarray(4, size + 4).toString('utf8'));
        buffer = buffer.subarray(size + 4);
        const pending = this.pending.get(message.id);
        if (pending) {
          clearTimeout(pending.timer);
          this.pending.delete(message.id);
          if (message.code < 0)
            pending.reject(new Error('BettboxCore ' + message.method + ' failed: ' + JSON.stringify(message.data)));
          else pending.resolve(message.data);
        }
      }
    });
    this.socket.on('error', (err) => this.rejectPending(err));
    this.socket.on('close', () => this.rejectPending(new Error('BettboxCore IPC closed')));
    const initialized = await this.call('initClash', { 'home-dir': this.directory, version: 1 });
    if (initialized !== true) throw new Error('BettboxCore initialization failed');
    return this;
  }
  rejectPending(err) {
    for (const item of this.pending.values()) {
      clearTimeout(item.timer);
      item.reject(err);
    }
    this.pending.clear();
  }
  call(method, data, timeout = 15000) {
    const id = String(this.nextId++);
    const payload = Buffer.from(
      JSON.stringify({
        id,
        method,
        data: data === undefined ? null : typeof data === 'string' ? data : JSON.stringify(data),
      }),
    );
    const frame = Buffer.alloc(payload.length + 4);
    frame.writeUInt32LE(payload.length);
    payload.copy(frame, 4);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error('BettboxCore ' + method + ' timed out'));
      }, timeout);
      this.pending.set(id, { resolve, reject, timer });
      this.socket.write(frame);
    });
  }
  async load(config, selected = {}) {
    const YAML = require('yaml');
    fs.writeFileSync(path.join(this.directory, 'config.yaml'), YAML.stringify(config));
    const rawConfig = await this.call('getConfig', { path: path.join(this.directory, 'config.yaml') });
    const result = await this.call(
      'setupConfig',
      { config: rawConfig, 'selected-map': selected, 'override-test-url': false, 'test-url': 'http://127.0.0.1/' },
      30000,
    );
    if (result !== '') throw new Error('BettboxCore configuration rejected: ' + result);
    const loaded = await this.call('getProxies');
    for (const group of config['proxy-groups'] || []) {
      if (!loaded[group.name]) throw new Error('BettboxCore did not load group: ' + group.name);
    }
    await this.call('startListener');
  }
  async select(group, node) {
    const result = await this.call('changeProxy', { 'group-name': group, 'proxy-name': node });
    if (result !== '') throw new Error('BettboxCore selection failed: ' + result);
  }
  async stop() {
    if (this.socket && !this.socket.destroyed) {
      await this.call('stopListener', undefined, 2000).catch(() => {});
      await this.call('shutdown', undefined, 2000).catch(() => {});
      this.socket.destroy();
    }
    this.server?.close();
    if (this.process && this.process.exitCode === null) {
      const exited = once(this.process, 'exit');
      this.process.kill();
      await exited;
    }
  }
}
function defaultCorePath() {
  return process.env.BETTBOX_CORE_PATH || 'C:/Program Files/Bettbox/BettboxCore.exe';
}
function testDirectory(label = 'core') {
  return path.resolve(__dirname, '../../.test-runtime', label + '-' + crypto.randomUUID());
}
module.exports = { BettboxCore, defaultCorePath, testDirectory, cleanProxyEnvironment };
