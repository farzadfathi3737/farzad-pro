'use strict';
// V2Gate — single-port Xray proxy + config panel.
//
//   ┌──────────────┐   HTTP(S) on $PORT   ┌────────────┐  127.0.0.1:1010x  ┌──────┐
//   │ client/app   │ ───────────────────▶ │  this app  │ ────────────────▶ │ xray │ ──▶ internet
//   └──────────────┘  WS upgrade / panel  └────────────┘  (per protocol)   └──────┘
//
// Everything a visitor sees on normal URLs is a plain placeholder page; the panel
// lives under PANEL_PATH and the subscription under SUB_PATH/<token>.

const http = require('http');
const https = require('https');
const net = require('net');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const QR = require('./qr');

const { settings, state, updateState, hashPassword, verifyPassword, randomToken } = require('./config');
const xray = require('./xray');
const links = require('./links');
const panel = require('./panel');

const startedAt = Date.now();
const log = (...a) => console.log('[v2gate]', ...a);

// ---- helpers -----------------------------------------------------------------
function send(res, status, body, headers = {}) {
  const h = { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', ...headers };
  if (typeof body === 'string' || Buffer.isBuffer(body)) h['Content-Length'] = Buffer.byteLength(body);
  res.writeHead(status, h);
  res.end(body);
}
const redirect = (res, to) => send(res, 302, '', { Location: to });
const notFound = (res) => send(res, 404, '<h1>404 Not Found</h1>');

function readBody(req, limit = 10 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function parseForm(body) {
  const out = {};
  for (const [k, v] of new URLSearchParams(body)) out[k] = v;
  return out;
}

function parseCookies(req) {
  const out = {};
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function clientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();
  return req.socket.remoteAddress || '';
}

function isSecureRequest(req) {
  if (req.socket.encrypted) return true;
  const xfp = req.headers['x-forwarded-proto'];
  return xfp ? String(xfp).split(',')[0].trim() === 'https' : settings.tlsMode === 'proxy';
}

function baseUrl(req) {
  const proto = isSecureRequest(req) ? 'https' : 'http';
  const host = req.headers['x-forwarded-host'] || req.headers.host || `${settings.host}:${settings.port}`;
  return `${proto}://${host}`;
}

function uptimeString() {
  let s = Math.floor((Date.now() - startedAt) / 1000);
  const d = Math.floor(s / 86400); s %= 86400;
  const h = Math.floor(s / 3600); s %= 3600;
  const m = Math.floor(s / 60);
  return `${d ? d + ' روز ' : ''}${h} ساعت ${m} دقیقه`;
}

// ---- sessions (signed cookie) --------------------------------------------------
const COOKIE = 'v2g_sess';
const SESSION_TTL = 7 * 24 * 3600 * 1000;

function sign(payload) {
  return crypto.createHmac('sha256', state.sessionSecret).update(payload).digest('base64url');
}
function makeSession() {
  const exp = String(Date.now() + SESSION_TTL);
  return `${exp}.${sign(exp)}`;
}
function validSession(token) {
  if (!token) return false;
  const [exp, sig] = token.split('.');
  if (!exp || !sig) return false;
  const expected = sign(exp);
  if (expected.length !== sig.length || !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig))) return false;
  return Number(exp) > Date.now();
}
function sessionCookie(req, value, maxAge) {
  const secure = isSecureRequest(req) ? '; Secure' : '';
  return `${COOKIE}=${value}; Path=${settings.panelPath}; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure}`;
}

// Brute-force guard for the login form.
const failures = new Map(); // ip → { count, until }
function loginAllowed(ip) {
  const f = failures.get(ip);
  return !(f && f.until > Date.now());
}
function noteFailure(ip) {
  const f = failures.get(ip) || { count: 0, until: 0 };
  f.count += 1;
  if (f.count >= 5) {
    f.until = Date.now() + 10 * 60 * 1000;
    f.count = 0;
  }
  failures.set(ip, f);
}

// ---- QR cache -------------------------------------------------------------------
const qrCache = new Map();
async function qr(text) {
  if (qrCache.has(text)) return qrCache.get(text);
  const url = QR.toDataUri(text, { level: 'M', scale: 4 });
  if (qrCache.size > 200) qrCache.clear();
  qrCache.set(text, url);
  return url;
}

// ---- panel ------------------------------------------------------------------------
async function handlePanel(req, res, url) {
  const p = settings.panelPath;
  const sub = url.pathname.slice(p.length) || '/';
  const ip = clientIp(req);

  // First run: no password yet → setup form.
  if (!state.panelPasswordHash) {
    if (req.method === 'POST' && sub === '/setup') {
      const form = parseForm(await readBody(req));
      if (!form.password || form.password.length < 8) {
        return send(res, 400, panel.setupPage({ action: `${p}/setup`, error: 'رمز باید حداقل ۸ کاراکتر باشد.' }));
      }
      if (form.password !== form.confirm) {
        return send(res, 400, panel.setupPage({ action: `${p}/setup`, error: 'تکرار رمز مطابقت ندارد.' }));
      }
      updateState({ panelPasswordHash: hashPassword(form.password) });
      log('panel password set');
      return redirect(res, p);
    }
    return send(res, 200, panel.setupPage({ action: `${p}/setup` }));
  }

  const cookies = parseCookies(req);
  const authed = validSession(cookies[COOKIE]);

  if (sub === '/login' && req.method === 'POST') {
    if (!loginAllowed(ip)) {
      return send(res, 429, panel.loginPage({ action: `${p}/login`, error: 'تلاش‌های ناموفق زیاد. ۱۰ دقیقه بعد دوباره امتحان کنید.' }));
    }
    const form = parseForm(await readBody(req));
    if (verifyPassword(form.password || '', state.panelPasswordHash)) {
      failures.delete(ip);
      return send(res, 302, '', { Location: p, 'Set-Cookie': sessionCookie(req, makeSession(), SESSION_TTL / 1000) });
    }
    noteFailure(ip);
    return send(res, 401, panel.loginPage({ action: `${p}/login`, error: 'رمز عبور اشتباه است.' }));
  }

  if (!authed) return send(res, 200, panel.loginPage({ action: `${p}/login` }));

  if (req.method === 'POST') {
    if (sub === '/logout') {
      return send(res, 302, '', { Location: p, 'Set-Cookie': sessionCookie(req, '', 0) });
    }
    if (sub === '/restart') {
      await xray.restart();
      return redirect(res, p);
    }
    if (sub === '/rotate') {
      updateState({ uuid: crypto.randomUUID(), trojanPassword: randomToken(12), subToken: randomToken(16) });
      qrCache.clear();
      await xray.restart();
      log('credentials rotated');
      return redirect(res, p);
    }
    return notFound(res);
  }

  if (sub === '/' || sub === '') {
    const configs = links.allConfigs();
    const subUrl = links.subscriptionUrl(baseUrl(req));
    const qrs = { __sub: await qr(subUrl) };
    for (const c of configs) qrs[c.key] = await qr(c.link);
    return send(
      res,
      200,
      panel.dashboard({
        panelPath: p,
        host: settings.host,
        publicPort: settings.publicPort,
        tlsMode: settings.tlsMode,
        xray: xray.status(),
        xrayVersion: xrayVersionString,
        configs,
        subUrl,
        uptime: uptimeString(),
        qrs,
      })
    );
  }
  return notFound(res);
}

// ---- subscription -------------------------------------------------------------------
function handleSubscription(req, res, url) {
  const token = url.pathname.slice(settings.subPath.length + 1).split('/')[0];
  if (!token || token.length !== state.subToken.length ||
      !crypto.timingSafeEqual(Buffer.from(token), Buffer.from(state.subToken))) {
    return notFound(res);
  }
  const format = url.searchParams.get('format') || 'base64';
  const common = {
    'Profile-Title': 'base64:' + Buffer.from(settings.configName).toString('base64'),
    'Profile-Update-Interval': '12',
    'Subscription-Userinfo': 'upload=0; download=0; total=0; expire=0',
  };
  if (format === 'raw') {
    return send(res, 200, links.subscriptionRaw(), { ...common, 'Content-Type': 'text/plain; charset=utf-8' });
  }
  if (format === 'clash') {
    return send(res, 200, links.clashYaml(), {
      ...common,
      'Content-Type': 'text/yaml; charset=utf-8',
      'Content-Disposition': 'attachment; filename="v2gate.yaml"',
    });
  }
  return send(res, 200, links.subscriptionBase64(), { ...common, 'Content-Type': 'text/plain; charset=utf-8' });
}

// ---- HTTP request router -------------------------------------------------------------
async function onRequest(req, res) {
  try {
    const url = new URL(req.url, 'http://localhost');
    const p = url.pathname;

    if (p === '/health' || p === '/healthz') {
      const st = xray.status();
      return send(res, st.running ? 200 : 503, JSON.stringify({ ok: st.running, uptime: Date.now() - startedAt }), {
        'Content-Type': 'application/json',
      });
    }
    if (p === settings.panelPath || p.startsWith(settings.panelPath + '/')) return await handlePanel(req, res, url);
    if (p.startsWith(settings.subPath + '/')) return handleSubscription(req, res, url);

    // A proxy path hit without an Upgrade header (e.g. a scanner) → plain 404.
    if (xray.routes().has(p)) return notFound(res);

    if (p === '/') return send(res, 200, panel.decoyPage());
    return notFound(res);
  } catch (err) {
    log('request error', err.message);
    if (!res.headersSent) send(res, 500, '<h1>500</h1>');
  }
}

// ---- WebSocket / HTTPUpgrade reverse proxy → xray ---------------------------------------
// We do not speak WebSocket ourselves: the raw upgrade request is replayed to the
// xray inbound for that path and the two sockets are piped together.
function onUpgrade(req, socket, head) {
  const pathname = req.url.split('?')[0];
  const port = xray.routes().get(pathname);
  if (!port) {
    socket.end('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
    return;
  }

  const upstream = net.connect({ host: '127.0.0.1', port });
  socket.setNoDelay(true);
  socket.setTimeout(0);
  upstream.setNoDelay(true);

  const cleanup = () => {
    socket.destroy();
    upstream.destroy();
  };

  upstream.on('connect', () => {
    // Rebuild the request line + headers exactly as received.
    let raw = `${req.method} ${req.url} HTTP/${req.httpVersion}\r\n`;
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      raw += `${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}\r\n`;
    }
    raw += '\r\n';
    upstream.write(raw);
    if (head && head.length) upstream.write(head);
    socket.pipe(upstream);
    upstream.pipe(socket);
  });

  upstream.on('error', cleanup);
  socket.on('error', cleanup);
  upstream.on('close', () => socket.destroy());
  socket.on('close', () => upstream.destroy());
}

// ---- TLS (self-signed) -----------------------------------------------------------------
function loadOrCreateSelfSignedCert() {
  const certFile = path.join(settings.dataDir, 'cert.pem');
  const keyFile = path.join(settings.dataDir, 'key.pem');
  if (fs.existsSync(certFile) && fs.existsSync(keyFile)) {
    const x = new crypto.X509Certificate(fs.readFileSync(certFile));
    if (new Date(x.validTo).getTime() - Date.now() > 7 * 86400 * 1000) {
      return { cert: fs.readFileSync(certFile), key: fs.readFileSync(keyFile) };
    }
    log('TLS certificate expiring soon, regenerating');
  }
  // Node has no X.509 *issuing* API, so we lean on the openssl CLI (present on
  // virtually every Linux image; the Dockerfile installs it explicitly).
  const san = net.isIP(settings.host) ? `IP:${settings.host}` : `DNS:${settings.host}`;
  try {
    execFileSync(
      'openssl',
      ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '825',
        '-keyout', keyFile, '-out', certFile,
        '-subj', `/CN=${settings.host}`, '-addext', `subjectAltName=${san}`],
      { stdio: ['ignore', 'ignore', 'pipe'] }
    );
  } catch (err) {
    throw new Error(
      `TLS_MODE=self needs the "openssl" command to create a certificate (${err.message.split('\n')[0]}). ` +
      'Install openssl, or set TLS_MODE=off / TLS_MODE=proxy.'
    );
  }
  fs.chmodSync(keyFile, 0o600);
  log('generated self-signed certificate for', settings.host);
  return { cert: fs.readFileSync(certFile), key: fs.readFileSync(keyFile) };
}

// ---- public IP discovery ------------------------------------------------------------------
function fetchText(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { timeout: 6000, headers: { 'User-Agent': 'curl/8' } }, (res) => {
      let d = '';
      res.on('data', (c) => (d += c));
      res.on('end', () => resolve(d.trim()));
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('timeout')));
  });
}
async function discoverHost() {
  for (const u of ['https://api64.ipify.org', 'https://checkip.amazonaws.com', 'https://ifconfig.me/ip']) {
    try {
      const ip = await fetchText(u);
      if (net.isIP(ip)) return ip;
    } catch { /* try next */ }
  }
  return null;
}

// ---- main -----------------------------------------------------------------------------------
let xrayVersionString = 'unknown';

async function main() {
  log(`starting on port ${settings.port} (tls mode: ${settings.tlsMode}${settings.onPaaS ? ', PaaS detected' : ''})`);

  if (!settings.host) {
    const ip = await discoverHost();
    settings.host = ip || '127.0.0.1';
    log(`public host not set; using ${settings.host}${ip ? '' : ' (could not detect public IP — set HOST)'}`);
  }

  await xray.ensureBinary();
  xrayVersionString = await xray.version();
  log(xrayVersionString);
  xray.start();

  let server;
  if (settings.tlsMode === 'self') {
    server = https.createServer(loadOrCreateSelfSignedCert(), onRequest);
  } else {
    server = http.createServer(onRequest);
  }
  server.on('upgrade', onUpgrade);
  server.keepAliveTimeout = 65000;
  server.headersTimeout = 70000;
  server.requestTimeout = 0;

  server.listen(settings.port, '0.0.0.0', () => {
    const scheme = settings.tlsMode === 'self' ? 'https' : 'http';
    log(`listening on ${scheme}://0.0.0.0:${settings.port}`);
    log(`panel: ${settings.panelPath}   subscription: ${settings.subPath}/<token>`);
    log(`clients connect to ${settings.host}:${settings.publicPort} ${links.tlsOn() ? 'with' : 'without'} TLS`);
  });

  const shutdown = async (sig) => {
    log(`${sig} received, shutting down`);
    server.close();
    await xray.stop();
    process.exit(0);
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main().catch((err) => {
  console.error('[v2gate] fatal:', err);
  process.exit(1);
});
