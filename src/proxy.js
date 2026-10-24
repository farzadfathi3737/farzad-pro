'use strict';
// Native VLESS and Trojan servers. Each takes a Duplex stream (a WebSocket or
// HTTPUpgrade connection), parses the protocol header, opens a TCP connection to
// the requested destination and relays bytes in both directions.
//
// VLESS request:  ver(1) uuid(16) addonsLen(1) addons(n) cmd(1) port(2) atyp(1) addr(...) payload
// VLESS response: ver(1) addonsLen(1)=0
// Trojan request: sha224hex(password)(56) CRLF cmd(1) atyp(1) addr(...) port(2) CRLF payload
//
// UDP is supported only for DNS (port 53): VLESS/Trojan UDP packets are length-
// prefixed, which is exactly the wire format of DNS-over-TCP, so they are relayed
// to a TCP resolver unchanged.

const net = require('net');
const crypto = require('crypto');
const { settings, state } = require('./config');

const CMD_TCP = 1, CMD_UDP = 2;
const DNS_RESOLVER = settings.dnsResolver;

const stats = { active: 0, total: 0, bytesIn: 0, bytesOut: 0, errors: 0 };

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
      (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127);
  }
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    return l === '::1' || l === '::' || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe80') ||
      l.startsWith('::ffff:127.') || l.startsWith('::ffff:10.') || l.startsWith('::ffff:192.168.');
  }
  return false;
}

function isBlockedHost(host) {
  if (!settings.blockPrivate) return false;
  if (net.isIP(host)) return isPrivateIp(host);
  const h = host.toLowerCase();
  return h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal');
}

// ---- header parsers ---------------------------------------------------------------
function readAddress(buf, off, atypMap) {
  const atyp = buf[off];
  off += 1;
  const kind = atypMap[atyp];
  if (!kind) throw new Error(`bad address type ${atyp}`);
  if (kind === 'ipv4') {
    if (buf.length < off + 4) return null;
    return { host: Array.from(buf.subarray(off, off + 4)).join('.'), off: off + 4 };
  }
  if (kind === 'ipv6') {
    if (buf.length < off + 16) return null;
    const parts = [];
    for (let i = 0; i < 16; i += 2) parts.push(buf.readUInt16BE(off + i).toString(16));
    return { host: parts.join(':'), off: off + 16 };
  }
  // domain
  if (buf.length < off + 1) return null;
  const len = buf[off];
  off += 1;
  if (buf.length < off + len) return null;
  return { host: buf.toString('utf8', off, off + len), off: off + len };
}

const uuidBytes = () => Buffer.from(state.uuid.replace(/-/g, ''), 'hex');

/** Returns null if more bytes are needed, throws on protocol/auth error. */
function parseVless(buf) {
  if (buf.length < 18) return null;
  if (buf[0] !== 0) throw new Error('vless: unsupported version');
  if (!crypto.timingSafeEqual(buf.subarray(1, 17), uuidBytes())) throw new Error('vless: bad uuid');
  const addonsLen = buf[17];
  let off = 18 + addonsLen;
  if (buf.length < off + 4) return null;
  const cmd = buf[off];
  off += 1;
  const port = buf.readUInt16BE(off);
  off += 2;
  const addr = readAddress(buf, off, { 1: 'ipv4', 2: 'domain', 3: 'ipv6' });
  if (!addr) return null;
  return { cmd, port, host: addr.host, payload: buf.subarray(addr.off), responseHeader: Buffer.from([0, 0]) };
}

const trojanHash = () => crypto.createHash('sha224').update(state.trojanPassword).digest('hex');

function parseTrojan(buf) {
  if (buf.length < 58) return null;
  const given = buf.subarray(0, 56);
  const expected = Buffer.from(trojanHash());
  if (!crypto.timingSafeEqual(given, expected)) throw new Error('trojan: bad password');
  if (buf[56] !== 0x0d || buf[57] !== 0x0a) throw new Error('trojan: bad header');
  let off = 58;
  if (buf.length < off + 2) return null;
  const cmd = buf[off];
  off += 1;
  const addr = readAddress(buf, off, { 1: 'ipv4', 3: 'domain', 4: 'ipv6' });
  if (!addr) return null;
  off = addr.off;
  if (buf.length < off + 4) return null;
  const port = buf.readUInt16BE(off);
  off += 2;
  if (buf[off] !== 0x0d || buf[off + 1] !== 0x0a) throw new Error('trojan: bad header');
  off += 2;
  return { cmd, port, host: addr.host, payload: buf.subarray(off), responseHeader: null };
}

// ---- relay ----------------------------------------------------------------------------
function relay(stream, req, log) {
  let target;
  if (req.cmd === CMD_TCP) {
    if (isBlockedHost(req.host)) throw new Error(`blocked destination ${req.host}`);
    target = net.connect({ host: req.host, port: req.port });
  } else if (req.cmd === CMD_UDP) {
    if (req.port !== 53) throw new Error('udp: only DNS (port 53) is supported');
    target = net.connect({ host: DNS_RESOLVER, port: settings.dnsResolverPort });
  } else {
    throw new Error(`unsupported command ${req.cmd}`);
  }
  target.setNoDelay(true);
  target.setTimeout(settings.idleTimeout, () => target.destroy());

  stats.active += 1;
  stats.total += 1;
  let done = false;
  const finish = (why) => {
    if (done) return;
    done = true;
    stats.active -= 1;
    if (why) log(`${req.host}:${req.port} closed: ${why}`);
    target.destroy();
    stream.destroy();
  };

  target.on('connect', () => {
    if (req.responseHeader) stream.write(req.responseHeader);
    if (req.payload.length) target.write(req.payload);
    stream.on('data', (d) => {
      stats.bytesIn += d.length;
      if (!target.write(d)) {
        stream.pause();
        target.once('drain', () => stream.resume());
      }
    });
    target.on('data', (d) => {
      stats.bytesOut += d.length;
      if (!stream.write(d)) {
        target.pause();
        stream.once('drain', () => target.resume());
      }
    });
    stream.resume();
  });
  target.on('error', (e) => { stats.errors += 1; finish(e.code || e.message); });
  target.on('close', () => finish());
  stream.on('error', (e) => finish(e.message));
  stream.on('close', () => finish());
  stream.on('end', () => target.end());
  target.on('end', () => stream.end());
}

/**
 * Handle one proxy connection. `protocol` is 'vless' | 'trojan'.
 * The stream is paused until the header is parsed, then handed to relay().
 */
function handle(stream, protocol, log = () => {}) {
  const parse = protocol === 'vless' ? parseVless : parseTrojan;
  let head = Buffer.alloc(0);
  const headerTimer = setTimeout(() => { log('header timeout'); stream.destroy(); }, 10000);

  const onData = (chunk) => {
    head = head.length ? Buffer.concat([head, chunk]) : chunk;
    let req;
    try {
      req = parse(head);
    } catch (e) {
      clearTimeout(headerTimer);
      stats.errors += 1;
      log(`rejected: ${e.message}`);
      stream.destroy();
      return;
    }
    if (!req) {
      if (head.length > 8192) { clearTimeout(headerTimer); stream.destroy(); }
      return;
    }
    clearTimeout(headerTimer);
    stream.removeListener('data', onData);
    stream.pause(); // hold any further bytes until the target socket is connected
    try {
      relay(stream, req, log);
    } catch (e) {
      stats.errors += 1;
      log(`rejected: ${e.message}`);
      stream.destroy();
    }
  };
  stream.on('data', onData);
  stream.on('error', () => clearTimeout(headerTimer));
}

// ---- client-side header builders (used by the panel self-test) -----------------------
function buildVlessHeader(host, port) {
  const h = Buffer.from(host, 'utf8');
  const out = Buffer.alloc(1 + 16 + 1 + 1 + 2 + 1 + 1 + h.length);
  let off = 0;
  out[off++] = 0;
  uuidBytes().copy(out, off); off += 16;
  out[off++] = 0;           // no addons
  out[off++] = CMD_TCP;
  out.writeUInt16BE(port, off); off += 2;
  out[off++] = 2;           // domain
  out[off++] = h.length;
  h.copy(out, off);
  return out;
}

function buildTrojanHeader(host, port) {
  const h = Buffer.from(host, 'utf8');
  return Buffer.concat([
    Buffer.from(trojanHash()), Buffer.from([0x0d, 0x0a, CMD_TCP, 3, h.length]), h,
    Buffer.from([(port >> 8) & 0xff, port & 0xff, 0x0d, 0x0a]),
  ]);
}

module.exports = { handle, stats, buildVlessHeader, buildTrojanHeader, isBlockedHost };
