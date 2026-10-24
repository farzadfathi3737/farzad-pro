'use strict';
// Minimal RFC 6455 WebSocket implementation (server accept + client connect),
// exposing each connection as a Duplex stream of raw bytes. Text/binary frames
// are both treated as opaque payload, which is what proxy transports need.

const crypto = require('crypto');
const net = require('net');
const tls = require('tls');
const { Duplex } = require('stream');

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

function acceptKey(key) {
  return crypto.createHash('sha1').update(key + GUID).digest('base64');
}

/** Build one frame. `mask` → client-to-server frames must be masked. */
function encodeFrame(payload, opcode = 0x2, mask = false) {
  const len = payload.length;
  let header;
  if (len < 126) header = Buffer.from([0x80 | opcode, len]);
  else if (len < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x80 | opcode;
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x80 | opcode;
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }
  if (!mask) return Buffer.concat([header, payload]);
  header[1] |= 0x80;
  const key = crypto.randomBytes(4);
  const masked = Buffer.allocUnsafe(len);
  for (let i = 0; i < len; i++) masked[i] = payload[i] ^ key[i & 3];
  return Buffer.concat([header, key, masked]);
}

/**
 * Wraps a raw socket (already past the HTTP handshake) as a Duplex.
 * Reading yields de-framed payload; writing emits binary frames.
 */
class WebSocketStream extends Duplex {
  constructor(socket, { maskOutgoing = false, initialData = null } = {}) {
    super();
    this.socket = socket;
    this.maskOutgoing = maskOutgoing;
    this.buf = Buffer.alloc(0);
    this.fragments = [];
    this._wsClosed = false;

    socket.on('data', (d) => this._feed(d));
    socket.on('end', () => this.push(null));
    socket.on('close', () => this._teardown());
    socket.on('error', (e) => { this.destroy(e); });
    if (initialData && initialData.length) this._feed(initialData);
  }

  _feed(chunk) {
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
    for (;;) {
      const frame = this._parseFrame();
      if (!frame) break;
      const { fin, opcode, payload } = frame;
      switch (opcode) {
        case 0x0: // continuation
        case 0x1: // text
        case 0x2: // binary
          this.fragments.push(payload);
          if (fin) {
            const data = this.fragments.length === 1 ? this.fragments[0] : Buffer.concat(this.fragments);
            this.fragments = [];
            if (!this.push(data)) this.socket.pause();
          }
          break;
        case 0x8: // close
          this._sendRaw(encodeFrame(payload.subarray(0, 2), 0x8, this.maskOutgoing));
          this.push(null);
          this.socket.end();
          return;
        case 0x9: // ping → pong
          this._sendRaw(encodeFrame(payload, 0xa, this.maskOutgoing));
          break;
        case 0xa: // pong
          break;
        default:
          this.destroy(new Error(`ws: bad opcode ${opcode}`));
          return;
      }
    }
  }

  _parseFrame() {
    const b = this.buf;
    if (b.length < 2) return null;
    const fin = (b[0] & 0x80) !== 0;
    const opcode = b[0] & 0x0f;
    const masked = (b[1] & 0x80) !== 0;
    let len = b[1] & 0x7f;
    let off = 2;
    if (len === 126) {
      if (b.length < 4) return null;
      len = b.readUInt16BE(2);
      off = 4;
    } else if (len === 127) {
      if (b.length < 10) return null;
      const big = b.readBigUInt64BE(2);
      if (big > BigInt(64 * 1024 * 1024)) {
        this.destroy(new Error('ws: frame too large'));
        return null;
      }
      len = Number(big);
      off = 10;
    }
    let key = null;
    if (masked) {
      if (b.length < off + 4) return null;
      key = b.subarray(off, off + 4);
      off += 4;
    }
    if (b.length < off + len) return null;
    let payload = b.subarray(off, off + len);
    if (masked) {
      const out = Buffer.allocUnsafe(len);
      for (let i = 0; i < len; i++) out[i] = payload[i] ^ key[i & 3];
      payload = out;
    } else {
      payload = Buffer.from(payload); // detach from the shared buffer
    }
    this.buf = b.subarray(off + len);
    return { fin, opcode, payload };
  }

  _sendRaw(frame) {
    if (!this._wsClosed && !this.socket.destroyed) this.socket.write(frame);
  }

  _read() {
    this.socket.resume();
  }

  _write(chunk, enc, cb) {
    if (this.socket.destroyed) return cb();
    const ok = this.socket.write(encodeFrame(chunk, 0x2, this.maskOutgoing));
    if (ok) cb();
    else this.socket.once('drain', cb);
  }

  _final(cb) {
    this._sendRaw(encodeFrame(Buffer.from([0x03, 0xe8]), 0x8, this.maskOutgoing)); // 1000 normal
    this.socket.end();
    cb();
  }

  _destroy(err, cb) {
    this._teardown();
    this.socket.destroy();
    cb(err);
  }

  _teardown() {
    if (this._wsClosed) return;
    this._wsClosed = true;
    this.push(null);
    this.emit('close');
  }
}

/** Server side: complete the handshake on an `upgrade` event and return the stream. */
function acceptWebSocket(req, socket, head) {
  const key = req.headers['sec-websocket-key'];
  if (!key || String(req.headers.upgrade || '').toLowerCase() !== 'websocket') {
    socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
    return null;
  }
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
      'Upgrade: websocket\r\n' +
      'Connection: Upgrade\r\n' +
      `Sec-WebSocket-Accept: ${acceptKey(key)}\r\n\r\n`
  );
  return new WebSocketStream(socket, { maskOutgoing: false, initialData: head });
}

/** Server side: HTTPUpgrade transport — a plain byte stream after the 101. */
function acceptHttpUpgrade(req, socket, head) {
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n');
  if (head && head.length) socket.unshift(head);
  return socket;
}

/**
 * Client side (used by the panel self-test): connect, do the handshake, return a
 * WebSocketStream. Supports ws:// and wss:// (with optional rejectUnauthorized=false).
 */
function connectWebSocket({ host, port, path, secure = false, headers = {}, servername, rejectUnauthorized = true, timeout = 8000 }) {
  return new Promise((resolve, reject) => {
    const key = crypto.randomBytes(16).toString('base64');
    const onConnect = () => {
      let req =
        `GET ${path} HTTP/1.1\r\n` +
        `Host: ${headers.Host || host}\r\n` +
        'Upgrade: websocket\r\nConnection: Upgrade\r\n' +
        `Sec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n`;
      for (const [k, v] of Object.entries(headers)) if (k !== 'Host') req += `${k}: ${v}\r\n`;
      socket.write(req + '\r\n');
    };
    const socket = secure
      ? tls.connect({ host, port, servername: servername || host, rejectUnauthorized }, onConnect)
      : net.connect({ host, port }, onConnect);

    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('ws: handshake timeout')); }, timeout);
    const onData = (d) => {
      buf = Buffer.concat([buf, d]);
      const idx = buf.indexOf('\r\n\r\n');
      if (idx === -1) return;
      clearTimeout(timer);
      socket.removeListener('data', onData);
      const header = buf.subarray(0, idx).toString();
      const status = /^HTTP\/1\.1 (\d+)/.exec(header);
      if (!status || status[1] !== '101') {
        socket.destroy();
        return reject(new Error(`ws: handshake failed (${status ? status[1] : 'no status'})`));
      }
      const expected = acceptKey(key);
      const got = /sec-websocket-accept:\s*(\S+)/i.exec(header);
      if (!got || got[1] !== expected) {
        socket.destroy();
        return reject(new Error('ws: bad Sec-WebSocket-Accept'));
      }
      resolve(new WebSocketStream(socket, { maskOutgoing: true, initialData: buf.subarray(idx + 4) }));
    };
    socket.on('data', onData);
    socket.on('error', (e) => { clearTimeout(timer); reject(e); });
  });
}

module.exports = { acceptWebSocket, acceptHttpUpgrade, connectWebSocket, WebSocketStream, encodeFrame };
