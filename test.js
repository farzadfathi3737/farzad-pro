// End-to-end test: local HTTP target <- VLESS/WS server <- hand-written VLESS client
'use strict';
const http = require('http');
const { spawn } = require('child_process');
const WebSocket = require('ws');

const UUID = 'bf7789c6-a217-4c23-9c4c-462bbfc9002f';
const PORT = 18080;
const TARGET_PORT = 18081;

// 1) a target web server
const target = http.createServer((req, res) => res.end('hello-from-target:' + req.headers.host));
target.listen(TARGET_PORT, '127.0.0.1');

// 2) the VLESS server under test
const srv = spawn(process.execPath, ['server.js'], {
  env: { ...process.env, PORT: String(PORT), UUID, WS_PATH: '/ws', LOG: '1' },
  stdio: ['ignore', 'inherit', 'inherit'],
});

function vlessHeader(host, port) {
  const id = Buffer.from(UUID.replace(/-/g, ''), 'hex');
  const h = Buffer.from(host);
  const b = Buffer.alloc(1 + 16 + 1 + 1 + 2 + 1 + 1 + h.length);
  let o = 0;
  b[o++] = 0;                // version
  id.copy(b, o); o += 16;    // uuid
  b[o++] = 0;                // addons len
  b[o++] = 1;                // cmd TCP
  b.writeUInt16BE(port, o); o += 2;
  b[o++] = 2;                // atyp domain
  b[o++] = h.length; h.copy(b, o);
  return b;
}

function run(name, fn) {
  return new Promise((resolve) => fn((ok, msg) => { console.log((ok ? 'PASS' : 'FAIL'), name, msg || ''); resolve(ok); }));
}

setTimeout(async () => {
  const results = [];

  results.push(await run('valid uuid -> proxied HTTP', (done) => {
    const ws = new WebSocket(`ws://127.0.0.1:${PORT}/ws`);
    let got = Buffer.alloc(0);
    ws.on('open', () => {
      const req = Buffer.from(`GET / HTTP/1.1\r\nHost: localhost:${TARGET_PORT}\r\nConnection: close\r\n\r\n`);
      ws.send(Buffer.concat([vlessHeader('localhost', TARGET_PORT), req]));
    });
    ws.on('message', (d) => { got = Buffer.concat([got, d]); });
    ws.on('close', () => {
      const s = got.toString();
      done(got[0] === 0 && got[1] === 0 && s.includes('hello-from-target'), s.slice(2, 60).replace(/\r?\n/g, ' '));
    });
    ws.on('error', (e) => done(false, e.message));
  }));

  results.push(await run('wrong uuid -> rejected', (done) => {
    const ws = new WebSocket(`ws://127.0.0.1:${PORT}/ws`);
    ws.on('open', () => {
      const h = vlessHeader('localhost', TARGET_PORT); h[5] ^= 0xff;
      ws.send(h);
    });
    ws.on('message', () => done(false, 'got data'));
    ws.on('close', () => done(true));
    ws.on('error', (e) => done(false, e.message));
  }));

  results.push(await run('wrong path -> 404', (done) => {
    const ws = new WebSocket(`ws://127.0.0.1:${PORT}/other`);
    ws.on('open', () => done(false, 'opened'));
    ws.on('error', (e) => done(/404/.test(e.message), e.message));
  }));

  results.push(await run('health endpoint', (done) => {
    http.get(`http://127.0.0.1:${PORT}/health`, (res) => done(res.statusCode === 200));
  }));

  srv.kill(); target.close();
  process.exit(results.every(Boolean) ? 0 : 1);
}, 500);
