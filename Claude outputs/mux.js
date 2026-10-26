'use strict';
// One public port, three kinds of traffic, told apart by the first bytes:
//   - TLS ClientHello whose SNI matches the Reality camouflage host → Xray's Reality inbound (loopback)
//   - any other TLS ClientHello                                  → our HTTPS server (self-signed)
//   - anything else (plain HTTP from a Worker / host proxy)      → our HTTP server
// The peeked bytes are pushed back with socket.unshift(), so the servers see a
// pristine stream.

const net = require('net');

/** Extract the SNI host from a TLS ClientHello, or null. */
function parseSni(buf) {
  try {
    if (buf.length < 44 || buf[0] !== 0x16) return null;
    let o = 5;
    if (buf[o] !== 0x01) return null;           // handshake type: ClientHello
    o += 4;                                     // type(1) + length(3)
    o += 2 + 32;                                // version + random
    o += 1 + buf[o];                            // session id
    o += 2 + buf.readUInt16BE(o);               // cipher suites
    o += 1 + buf[o];                            // compression methods
    if (o + 2 > buf.length) return null;
    const extEnd = Math.min(buf.length, o + 2 + buf.readUInt16BE(o));
    o += 2;
    while (o + 4 <= extEnd) {
      const type = buf.readUInt16BE(o);
      const len = buf.readUInt16BE(o + 2);
      o += 4;
      if (type === 0) {
        // server_name list: listLen(2) nameType(1) nameLen(2) name
        if (buf[o + 2] !== 0) return null;
        const nameLen = buf.readUInt16BE(o + 3);
        return buf.toString('utf8', o + 5, o + 5 + nameLen).toLowerCase();
      }
      o += len;
    }
  } catch { /* malformed */ }
  return null;
}

/** Bytes needed to hold the whole first TLS record (or 0 if not TLS). */
function tlsRecordLength(buf) {
  if (buf.length < 5 || buf[0] !== 0x16) return 0;
  return 5 + buf.readUInt16BE(3);
}

/**
 * createMux({ httpServer, httpsPort (loopback port of the HTTPS server) | null, reality: () => ({ port, sni }) | null, log })
 * returns a net.Server; call .listen() on it (several times for several ports is fine
 * by creating several muxes).
 */
function splice(socket, head, port) {
  const up = net.connect({ host: '127.0.0.1', port });
  up.setNoDelay(true);
  up.on('error', () => socket.destroy());
  socket.on('close', () => up.destroy());
  up.on('close', () => socket.destroy());
  up.on('connect', () => { if (head.length) up.write(head); socket.pipe(up); up.pipe(socket); socket.resume(); });
}

function createMux({ httpServer, httpsPort, reality, log = () => {}, onDecision = () => {} }) {
  const stats = { http: 0, https: 0, reality: 0, dropped: 0 };

  const server = net.createServer((socket) => {
    socket.on('error', () => {});
    let buf = Buffer.alloc(0);
    let decided = false;

    const decide = () => {
      if (decided) return;
      decided = true;
      clearTimeout(timer);
      socket.removeListener('data', onData);
      socket.pause();

      if (buf.length && buf[0] === 0x16) {
        const sni = parseSni(buf);
        const r = reality && reality();
        const ip = socket.remoteAddress;
        if (r && sni && sni === r.sni) {
          stats.reality++;
          onDecision({ kind: 'reality', note: 'tls → reality', sni, ip });
          splice(socket, buf, r.port);
          return;
        }
        if (httpsPort) {
          // The TLS server must see the ClientHello through its own handle, so the
          // peeked bytes are replayed over a loopback connection instead of unshift().
          stats.https++;
          onDecision({ kind: 'https', note: 'tls → https (direct)', sni, ip });
          splice(socket, buf, httpsPort);
          return;
        }
        stats.dropped++;
        onDecision({ kind: 'dropped', note: 'tls dropped: no certificate', sni, ip });
        socket.destroy();
        return;
      }
      stats.http++;
      if (!buf.length) { onDecision({ kind: 'empty', note: 'no data (closed)', ip: socket.remoteAddress }); socket.destroy(); return; }
      if (buf.length) socket.unshift(buf);
      httpServer.emit('connection', socket);
      socket.resume();
    };

    const onData = (d) => {
      buf = buf.length ? Buffer.concat([buf, d]) : d;
      const need = tlsRecordLength(buf);
      if (need === 0 || buf.length >= need || buf.length > 16384) decide();
    };
    const timer = setTimeout(decide, 3000); // slow or silent client: decide with what we have
    socket.on('data', onData);
    socket.on('close', () => clearTimeout(timer));
  });

  server.stats = stats;
  return server;
}

module.exports = { createMux, parseSni };
