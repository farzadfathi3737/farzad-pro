'use strict';
// Server-side half of the clean-IP finder: pick candidate Cloudflare edge IPs and
// verify, over TLS with the real SNI, that each one actually serves this panel
// (GET /health through it). The browser then times the survivors from the
// user's own network, which is the only vantage point that can judge "clean".

const tls = require('tls');
const { settings } = require('./config');

// Cloudflare IPv4 ranges (https://www.cloudflare.com/ips-v4). Weighted toward the
// ranges that are usually reported as usable from Iranian ISPs.
const RANGES = [
  { cidr: '188.114.96.0/20', w: 6 },
  { cidr: '162.159.192.0/22', w: 5 },
  { cidr: '162.159.195.0/24', w: 3 },
  { cidr: '162.158.0.0/15', w: 2 },
  { cidr: '104.16.0.0/13', w: 4 },
  { cidr: '104.24.0.0/14', w: 3 },
  { cidr: '172.64.0.0/13', w: 3 },
  { cidr: '141.101.64.0/18', w: 1 },
  { cidr: '108.162.192.0/18', w: 1 },
  { cidr: '190.93.240.0/20', w: 1 },
  { cidr: '198.41.128.0/17', w: 1 },
  { cidr: '173.245.48.0/20', w: 1 },
  { cidr: '103.21.244.0/22', w: 1 },
  { cidr: '103.22.200.0/22', w: 1 },
  { cidr: '103.31.4.0/22', w: 1 },
  { cidr: '131.0.72.0/22', w: 1 },
  { cidr: '197.234.240.0/22', w: 1 },
];

function ipToInt(ip) {
  return ip.split('.').reduce((a, b) => (a << 8) + Number(b), 0) >>> 0;
}
function intToIp(n) {
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

function randomIpInCidr(cidr) {
  const [base, bitsStr] = cidr.split('/');
  const bits = Number(bitsStr);
  const size = 2 ** (32 - bits);
  const start = ipToInt(base);
  // avoid .0 and .255 hosts
  for (;;) {
    const n = start + Math.floor(Math.random() * size);
    const last = n & 255;
    if (last !== 0 && last !== 255) return intToIp(n >>> 0);
  }
}

/** Pick `count` distinct random candidates across the weighted ranges. */
function candidates(count = 80) {
  const total = RANGES.reduce((s, r) => s + r.w, 0);
  const out = new Set();
  let guard = 0;
  while (out.size < count && guard++ < count * 20) {
    let r = Math.random() * total;
    const range = RANGES.find((x) => (r -= x.w) <= 0) || RANGES[0];
    out.add(randomIpInCidr(range.cidr));
  }
  return [...out];
}

/**
 * TLS-connect to ip:port with SNI = our host and fetch /health through it.
 * Resolves { ip, ok, ms, note }.
 */
function verifyOne(ip, { port = 443, timeout = 4000 } = {}) {
  return new Promise((resolve) => {
    const started = Date.now();
    let done = false;
    const finish = (ok, note) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { sock.destroy(); } catch { /* ignore */ }
      resolve({ ip, ok, ms: Date.now() - started, note });
    };
    const timer = setTimeout(() => finish(false, 'timeout'), timeout);
    const sock = tls.connect(
      { host: ip, port, servername: settings.host, rejectUnauthorized: settings.tlsMode !== 'self', ALPNProtocols: ['http/1.1'] },
      () => {
        sock.write(`GET /health HTTP/1.1\r\nHost: ${settings.host}\r\nUser-Agent: v2gate-scan\r\nConnection: close\r\n\r\n`);
      }
    );
    let buf = '';
    sock.on('data', (d) => {
      buf += d.toString('latin1');
      const m = /^HTTP\/1\.[01] (\d{3})/.exec(buf);
      if (m) {
        if (m[1] === '200' && /"ok":true/.test(buf)) finish(true, 'serves this panel');
        else if (buf.includes('\r\n\r\n')) finish(false, `HTTP ${m[1]}`);
      }
    });
    sock.on('end', () => finish(false, buf ? 'closed' : 'no response'));
    sock.on('error', (e) => finish(false, e.code || e.message));
  });
}

async function verifyMany(ips, { concurrency = 16, port = 443 } = {}) {
  const queue = [...ips];
  const results = [];
  async function worker() {
    while (queue.length) {
      const ip = queue.shift();
      results.push(await verifyOne(ip, { port }));
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, queue.length) }, worker));
  return results;
}

const isIPv4 = (s) => /^(\d{1,3}\.){3}\d{1,3}$/.test(s) && s.split('.').every((o) => Number(o) <= 255);

module.exports = { candidates, verifyMany, verifyOne, isIPv4, RANGES };
