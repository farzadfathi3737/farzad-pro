// VLESS-over-WebSocket exit node (pure Node.js, no Xray binary).
// Runs behind the host's TLS proxy; listens on plain HTTP/WS on $PORT.
//
// Env:
//   PORT      - port given by the host (default 8080)
//   UUID      - VLESS user id (required; comma-separate for several users)
//   WS_PATH   - websocket path, default "/ws"
//   LOG       - "1" to log each connection

'use strict';

const http = require('http');
const net = require('net');
const { WebSocketServer } = require('ws');

const PORT = Number(process.env.PORT || 8080);
const WS_PATH = process.env.WS_PATH || '/ws';
const LOG = process.env.LOG === '1';
const UUIDS = String(process.env.UUID || '')
  .split(',')
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

if (UUIDS.length === 0) {
  console.error('UUID env is required (e.g. UUID=bf7789c6-a217-4c23-9c4c-462bbfc9002f)');
  process.exit(1);
}

const UUID_BYTES = new Set(UUIDS.map((u) => u.replace(/-/g, '')));

function log(...a) {
  if (LOG) console.log(new Date().toISOString(), ...a);
}

// ---- VLESS request header -------------------------------------------------
// [1 ver][16 uuid][1 addonsLen][addons][1 cmd][2 port][1 atyp][addr][payload]
function parseVless(buf) {
  if (buf.length < 18) return { err: 'short header' };
  const version = buf[0];
  const id = buf.subarray(1, 17).toString('hex');
  if (!UUID_BYTES.has(id)) return { err: 'bad uuid' };
  const addonsLen = buf[17];
  let o = 18 + addonsLen;
  if (buf.length < o + 4) return { err: 'short header' };
  const cmd = buf[o++]; // 1 = TCP, 2 = UDP, 3 = MUX
  const port = buf.readUInt16BE(o);
  o += 2;
  const atyp = buf[o++];
  let host;
  if (atyp === 1) {
    if (buf.length < o + 4) return { err: 'short addr' };
    host = Array.from(buf.subarray(o, o + 4)).join('.');
    o += 4;
  } else if (atyp === 2) {
    const len = buf[o++];
    if (buf.length < o + len) return { err: 'short addr' };
    host = buf.subarray(o, o + len).toString('utf8');
    o += len;
  } else if (atyp === 3) {
    if (buf.length < o + 16) return { err: 'short addr' };
    const parts = [];
    for (let i = 0; i < 16; i += 2) parts.push(buf.readUInt16BE(o + i).toString(16));
    host = parts.join(':');
    o += 16;
  } else {
    return { err: 'bad atyp ' + atyp };
  }
  return { version, cmd, host, port, payload: buf.subarray(o) };
}

// ---- HTTP + WS ------------------------------------------------------------
const server = http.createServer((req, res) => {
  if (req.url === '/' || req.url === '/health') {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('ok\n');
    return;
  }
  res.writeHead(404);
  res.end();
});

const wss = new WebSocketServer({ noServer: true, perMessageDeflate: false });

server.on('upgrade', (req, socket, head) => {
  const url = req.url.split('?')[0];
  if (url !== WS_PATH) {
    socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => handle(ws, req));
});

function handle(ws, req) {
  const peer = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  let remote = null;
  let early = []; // data that arrives before the TCP connect finishes
  let closed = false;

  // Some clients send the first packet in Sec-WebSocket-Protocol (base64url) — "early data"
  const edHeader = req.headers['sec-websocket-protocol'];
  if (edHeader) {
    try {
      const b = Buffer.from(edHeader.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
      if (b.length) onFirst(b);
    } catch (_) {}
  }

  function close() {
    if (closed) return;
    closed = true;
    try { ws.terminate(); } catch (_) {}
    if (remote) remote.destroy();
  }

  function onFirst(buf) {
    const r = parseVless(buf);
    if (r.err) {
      log('reject', peer, r.err);
      return close();
    }
    if (r.cmd !== 1) {
      log('reject', peer, 'cmd', r.cmd, '(only TCP supported)');
      return close();
    }
    log('open', peer, '->', r.host + ':' + r.port);

    remote = net.connect({ host: r.host, port: r.port });
    remote.setNoDelay(true);
    remote.once('connect', () => {
      // VLESS response header: [version][0 addons]
      ws.send(Buffer.from([r.version, 0]));
      if (r.payload.length) remote.write(r.payload);
      for (const b of early) remote.write(b);
      early = null;
      remote.on('data', (d) => {
        if (ws.readyState === ws.OPEN) ws.send(d, (e) => e && close());
      });
      remote.on('end', () => close());
    });
    remote.on('error', (e) => { log('remote error', e.code || e.message); close(); });
    remote.on('close', () => close());
  }

  ws.on('message', (data) => {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    if (!remote) return onFirst(buf);
    if (early) early.push(buf);      // still connecting
    else remote.write(buf);
  });
  ws.on('close', close);
  ws.on('error', close);
}

server.listen(PORT, () => {
  console.log(`VLESS-WS exit listening on :${PORT} path=${WS_PATH} users=${UUIDS.length}`);
});
