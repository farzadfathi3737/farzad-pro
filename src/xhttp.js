'use strict';
// Native XHTTP (Xray "SplitHTTP") transport. No WebSocket, no Upgrade: the
// client uploads with ordinary POSTs and downloads with one long GET, so to a
// CDN or a middlebox it is plain HTTPS traffic.
//
//   packet-up (default behind CDNs):
//     GET  {path}/{session}            → 200, streamed body = server→client bytes
//     POST {path}/{session}/{seq}      → body = one client→server packet (reordered by seq)
//   stream-up:
//     GET  {path}/{session}            → as above
//     POST {path}/{session}            → streaming body = client→server bytes
//   stream-one:
//     POST {path}                      → streaming body up, streamed response down
//
// Each session is exposed to proxy.js as a Duplex, exactly like a WebSocket.

const { Duplex } = require('stream');
const { settings } = require('./config');

const SESSION_ID = /^[A-Za-z0-9_-]{1,64}$/;
const MAX_SESSIONS = 2000;
const MAX_PENDING_OUT = 4 * 1024 * 1024;   // bytes buffered before the GET arrives
const MAX_REORDER = 64;                      // out-of-order POSTs kept
const WAIT_FOR_GET_MS = 30 * 1000;

const RESP_HEADERS = {
  'Content-Type': 'text/event-stream',
  'Cache-Control': 'no-store',
  'X-Accel-Buffering': 'no',
  Connection: 'keep-alive',
};

class XhttpSession extends Duplex {
  constructor(id, log) {
    super({ readableHighWaterMark: 1024 * 1024 });
    this.id = id;
    this.log = log;
    this.res = null;           // the download response
    this.pendingOut = [];      // server→client bytes before the GET arrived
    this.pendingOutSize = 0;
    this.nextSeq = 0;
    this.reorder = new Map();  // seq → Buffer
    this.waiters = [];         // POST responses held back for backpressure
    this.lastActive = Date.now();
    this.createdAt = Date.now();
    this._xhClosed = false;
  }

  touch() { this.lastActive = Date.now(); }

  attachDownload(req, res) {
    this.touch();
    if (this.res) this.res.destroy();
    res.writeHead(200, RESP_HEADERS);
    res.flushHeaders();
    if (res.socket) res.socket.setNoDelay(true);
    this.res = res;
    for (const c of this.pendingOut) res.write(c);
    this.pendingOut = [];
    this.pendingOutSize = 0;
    res.on('close', () => this.destroy());
    res.on('error', () => this.destroy());
  }

  /** Returns true if the readable side still accepts data (else caller should wait). */
  pushUpload(seq, buf) {
    this.touch();
    if (seq < this.nextSeq) return true; // duplicate / retransmit
    if (seq !== this.nextSeq) {
      if (this.reorder.size >= MAX_REORDER) { this.destroy(new Error('xhttp: reorder window exceeded')); return true; }
      this.reorder.set(seq, buf);
      return true;
    }
    let ok = this.push(buf);
    this.nextSeq++;
    while (this.reorder.has(this.nextSeq)) {
      ok = this.push(this.reorder.get(this.nextSeq)) && ok;
      this.reorder.delete(this.nextSeq);
      this.nextSeq++;
    }
    return ok;
  }

  /** stream-up / stream-one: feed bytes in arrival order. */
  pushStream(buf) {
    this.touch();
    return this.push(buf);
  }

  _read() {
    const w = this.waiters;
    this.waiters = [];
    for (const cb of w) cb();
  }

  _write(chunk, enc, cb) {
    this.touch();
    if (this.res) {
      if (this.res.write(chunk)) cb();
      else this.res.once('drain', cb);
      return;
    }
    this.pendingOut.push(chunk);
    this.pendingOutSize += chunk.length;
    if (this.pendingOutSize > MAX_PENDING_OUT) return cb(new Error('xhttp: no download stream'));
    cb();
  }

  _final(cb) {
    if (this.res) this.res.end();
    cb();
  }

  _destroy(err, cb) {
    this._xhClosed = true;
    if (this.res) { try { this.res.end(); } catch { /* ignore */ } this.res = null; }
    for (const w of this.waiters) w();
    this.waiters = [];
    sessions.delete(this.id);
    cb(err);
  }
}

const sessions = new Map();

function getOrCreate(id, protocol, handle, log) {
  let s = sessions.get(id);
  if (s) return s;
  if (sessions.size >= MAX_SESSIONS) return null;
  s = new XhttpSession(id, log);
  sessions.set(id, s);
  s.on('close', () => sessions.delete(id));
  handle(s, protocol, (m) => log(`xhttp ${protocol} ${m}`));
  return s;
}

// Periodic sweep: sessions that never got their GET, or sat idle too long.
setInterval(() => {
  const now = Date.now();
  for (const s of sessions.values()) {
    if (!s.res && now - s.createdAt > WAIT_FOR_GET_MS) s.destroy(new Error('xhttp: no GET'));
    else if (now - s.lastActive > settings.idleTimeout) s.destroy(new Error('xhttp: idle'));
  }
}, 10000).unref();

function readAll(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { req.destroy(); reject(new Error('body too large')); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/**
 * Try to serve an XHTTP request. `routes` is Map<basePath, protocol>.
 * Returns true when the request was handled.
 */
function handleRequest(req, res, pathname, routes, handle, log) {
  for (const [base, protocol] of routes) {
    if (pathname !== base && !pathname.startsWith(base + '/')) continue;
    const rest = pathname.slice(base.length).split('/').filter(Boolean); // [session?, seq?]
    const [sid, seqStr] = rest;

    // stream-one: POST on the bare path, bidirectional on one request.
    if (!sid && req.method === 'POST') {
      const id = 'one-' + Math.random().toString(36).slice(2);
      const s = getOrCreate(id, protocol, handle, log);
      if (!s) { res.writeHead(503); res.end(); return true; }
      s.attachDownload(req, res);
      req.on('data', (d) => { if (!s.pushStream(d)) { req.pause(); s.waiters.push(() => req.resume()); } });
      req.on('end', () => s.push(null));
      req.on('error', () => s.destroy());
      return true;
    }
    if (!sid || !SESSION_ID.test(sid)) { res.writeHead(404); res.end('Not Found'); return true; }

    if (req.method === 'GET') {
      const s = getOrCreate(sid, protocol, handle, log);
      if (!s) { res.writeHead(503); res.end(); return true; }
      s.attachDownload(req, res);
      return true;
    }

    if (req.method === 'POST') {
      const s = getOrCreate(sid, protocol, handle, log);
      if (!s || s._xhClosed) { res.writeHead(s ? 410 : 503); res.end(); return true; }
      if (seqStr !== undefined) {
        // packet-up
        const seq = Number(seqStr);
        if (!Number.isInteger(seq) || seq < 0) { res.writeHead(400); res.end(); return true; }
        readAll(req, 4 * 1024 * 1024).then((body) => {
          const ok = s.pushUpload(seq, body);
          const finish = () => { res.writeHead(200, { 'Content-Length': '0', 'Cache-Control': 'no-store' }); res.end(); };
          if (ok || s._xhClosed) finish(); else s.waiters.push(finish);
        }).catch(() => { res.writeHead(400); res.end(); });
      } else {
        // stream-up
        req.on('data', (d) => { if (!s.pushStream(d)) { req.pause(); s.waiters.push(() => req.resume()); } });
        req.on('end', () => { s.push(null); res.writeHead(200, { 'Content-Length': '0' }); res.end(); });
        req.on('error', () => s.destroy());
      }
      return true;
    }
    res.writeHead(405); res.end();
    return true;
  }
  return false;
}

module.exports = { handleRequest, sessionCount: () => sessions.size };
