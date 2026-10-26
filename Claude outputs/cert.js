'use strict';
// Self-signed X.509 certificate generation in pure Node (no openssl binary):
// RSA-2048 key, sha256WithRSAEncryption, CN + subjectAltName, ~825 days.
// Node can generate keys and sign, but has no X.509 *issuing* API, so the
// certificate body (TBSCertificate) is DER-encoded by hand below.

const crypto = require('crypto');
const net = require('net');

// ---- minimal DER encoder -------------------------------------------------------------
function derLen(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  while (n > 0) { bytes.unshift(n & 0xff); n >>= 8; }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
function tlv(tag, body) {
  return Buffer.concat([Buffer.from([tag]), derLen(body.length), body]);
}
const SEQ = (...parts) => tlv(0x30, Buffer.concat(parts));
const SET = (...parts) => tlv(0x31, Buffer.concat(parts));
const INT = (buf) => {
  let b = Buffer.isBuffer(buf) ? buf : Buffer.from([buf]);
  while (b.length > 1 && b[0] === 0 && !(b[1] & 0x80)) b = b.subarray(1);
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return tlv(0x02, b);
};
const NULL = () => Buffer.from([0x05, 0x00]);
const OCTET = (b) => tlv(0x04, b);
const BITSTR = (b) => tlv(0x03, Buffer.concat([Buffer.from([0]), b]));
const UTF8 = (s) => tlv(0x0c, Buffer.from(s, 'utf8'));
const IA5 = (s) => tlv(0x16, Buffer.from(s, 'ascii'));
const EXPLICIT = (n, body) => tlv(0xa0 | n, body);
const CTX_PRIM = (n, body) => tlv(0x80 | n, body);
function OID(str) {
  const p = str.split('.').map(Number);
  const out = [40 * p[0] + p[1]];
  for (const v of p.slice(2)) {
    const stack = [v & 0x7f];
    let x = v >> 7;
    while (x > 0) { stack.unshift((x & 0x7f) | 0x80); x >>= 7; }
    out.push(...stack);
  }
  return tlv(0x06, Buffer.from(out));
}
function UTCTime(d) {
  const p = (n) => String(n).padStart(2, '0');
  return tlv(0x17, Buffer.from(
    `${p(d.getUTCFullYear() % 100)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`, 'ascii'));
}

// ---- certificate -----------------------------------------------------------------------
const OID_CN = '2.5.4.3';
const OID_SHA256_RSA = '1.2.840.113549.1.1.11';
const OID_SAN = '2.5.29.17';

function ipToBytes(ip) {
  if (net.isIPv4(ip)) return Buffer.from(ip.split('.').map(Number));
  // IPv6: expand
  const parts = ip.split('::');
  const head = parts[0] ? parts[0].split(':') : [];
  const tail = parts[1] ? parts[1].split(':') : [];
  const fill = 8 - head.length - tail.length;
  const groups = [...head, ...Array(Math.max(0, fill)).fill('0'), ...tail];
  const b = Buffer.alloc(16);
  groups.forEach((g, i) => b.writeUInt16BE(parseInt(g || '0', 16), i * 2));
  return b;
}

/**
 * generate({ commonName, altNames: ['example.com', '1.2.3.4'], days })
 * → { cert: PEM, key: PEM }
 */
function generate({ commonName, altNames = [], days = 825 } = {}) {
  const cn = commonName || altNames[0] || 'localhost';
  const names = [...new Set([cn, ...altNames])].filter(Boolean);

  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const spki = publicKey.export({ type: 'spki', format: 'der' });

  const name = SEQ(SET(SEQ(OID(OID_CN), UTF8(cn))));
  const now = new Date(Date.now() - 60 * 1000);
  const end = new Date(now.getTime() + days * 86400 * 1000);
  const serial = crypto.randomBytes(16);
  serial[0] &= 0x7f;

  const sanList = SEQ(...names.map((n) => (net.isIP(n) ? CTX_PRIM(7, ipToBytes(n)) : CTX_PRIM(2, IA5(n).subarray(2)))));
  // CTX_PRIM(2, …) needs the raw IA5 bytes (no inner tag): strip the IA5 TLV header above.
  const extensions = EXPLICIT(3, SEQ(SEQ(OID(OID_SAN), OCTET(sanList))));

  const sigAlg = SEQ(OID(OID_SHA256_RSA), NULL());
  const tbs = SEQ(
    EXPLICIT(0, INT(2)),          // version 3
    INT(serial),
    sigAlg,
    name,                         // issuer
    SEQ(UTCTime(now), UTCTime(end)),
    name,                         // subject
    spki,
    extensions
  );
  const signature = crypto.sign('sha256', tbs, privateKey);
  const cert = SEQ(tbs, sigAlg, BITSTR(signature));

  const pem = (label, der) => `-----BEGIN ${label}-----\n${der.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END ${label}-----\n`;
  return {
    cert: pem('CERTIFICATE', cert),
    key: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
}

module.exports = { generate };
