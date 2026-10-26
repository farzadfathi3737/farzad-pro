'use strict';
// V2Gate — single-port VLESS/Trojan proxy server + config panel, pure Node.js.
//
//   ┌──────────────┐   HTTP(S) on $PORT    ┌───────────────────────────┐
//   │ client/app   │ ────────────────────▶ │ this app                  │ ──▶ internet
//   └──────────────┘  WS / HTTPUpgrade     │  ws.js → proxy.js (VLESS, │
//                      panel, subscription │  Trojan) → net.connect    │
//                                          └───────────────────────────┘
// Everything a visitor sees on normal URLs is a plain placeholder page; the panel
// lives under PANEL_PATH and the subscription under SUB_PATH/<token>.

const http = require('http');
const https = require('https');
const net = require('net');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const QR = require('./qr');
const ws = require('./ws');
const proxy = require('./proxy');
const scan = require('./scan');
const xhttp = require('./xhttp');
const xray = require('./xray');
const reqlog = require('./reqlog');
const mux = require('./mux');
const certgen = require('./cert');
const { settings, state, updateState, setPublicOverride, routes, xhttpRoutes, paths, parseCleanIps, hashPassword, verifyPassword, randomToken } = require('./config');
const links = require('./links');
const panel = require('./panel');

const startedAt = Date.now();
const log = (...a) => console.log('[v2gate]', ...a);
const verbose = process.env.VERBOSE === '1' || process.env.VERBOSE === 'true';
const plog = verbose ? (...a) => console.log('[proxy]', ...a) : () => {};

// ---- helpers -----------------------------------------------------------------
function send(res, status, body, headers = {}) {
  const h = { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', ...headers };
  if (typeof body === 'string' || Buffer.isBuffer(body)) h['Content-Length'] = Buffer.byteLength(body);
  res.writeHead(status, h);
  res.end(body);
}
const redirect = (res, to) => send(res, 302, '', { Location: to });
const notFound = (res) => send(res, 404, '<h1>404 Not Found</h1>');

function readBody(req, limit = 16 * 1024) {
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

// Base URL for the subscription link. Built from the configured public address
// (same host/port the proxy configs use) so it stays correct behind a Worker or
// CDN that rewrites the Host header; falls back to the request when unset.
function baseUrl(req) {
  if (settings.host) {
    const https = settings.tlsMode !== 'off';
    const dflt = https ? 443 : 80;
    return `${https ? 'https' : 'http'}://${settings.host}${settings.publicPort === dflt ? '' : ':' + settings.publicPort}`;
  }
  const proto = isSecureRequest(req) ? 'https' : 'http';
  const host = req.headers['x-forwarded-host'] || req.headers.host || `${settings.host}:${settings.port}`;
  return `${proto}://${host}`;
}

// The public address the *browser* used to reach us — what clients should use too.
function requestAddress(req) {
  const secure = isSecureRequest(req);
  const raw = String(req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim();
  const m = /^(\[[^\]]+\]|[^:]+)(?::(\d+))?$/.exec(raw);
  const host = m ? m[1].replace(/^\[|\]$/g, '') : raw;
  const port = m && m[2] ? Number(m[2]) : secure ? 443 : 80;
  return { host, port, tls: secure ? 'proxy' : 'off' };
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
function qr(text) {
  if (qrCache.has(text)) return qrCache.get(text);
  const url = QR.toDataUri(text, { level: 'M', scale: 4 });
  if (qrCache.size > 400) qrCache.clear();
  qrCache.set(text, url);
  return url;
}

// ---- self-tests: act as a VLESS/Trojan client ---------------------------------------
// mode 'internal' → 127.0.0.1:$PORT (proves the engine + outbound internet).
// mode 'external' → the public address (Cloudflare → Worker → host → us): proves the
// whole chain passes WebSocket. `address` optionally replaces the host (a clean IP).
async function selfTest(mode = 'internal', address = '') {
  const target = new URL(process.env.SELFTEST_URL || 'http://www.gstatic.com/generate_204');
  const port = Number(target.port) || 80;
  const p = paths();
  const useVless = settings.enable.vlessWs;
  if (!useVless && !settings.enable.trojanWs) return { ok: false, text: 'هیچ کانفیگ WebSocket فعالی برای تست وجود ندارد.' };
  const started = Date.now();
  const external = mode === 'external';
  const connHost = external ? (address || settings.host) : '127.0.0.1';
  const connPort = external ? settings.publicPort : settings.port;
  const secure = external ? links.tlsOn() : settings.tlsMode === 'self';
  const where = external ? `${connHost}:${connPort} (SNI/Host ${settings.host})` : `127.0.0.1:${settings.port}`;
  let stream;
  try {
    stream = await ws.connectWebSocket({
      host: connHost,
      port: connPort,
      path: useVless ? p.vlessWs : p.trojanWs,
      secure,
      rejectUnauthorized: external && settings.tlsMode !== 'self',
      servername: settings.host,
      headers: { Host: settings.host },
      timeout: 12000,
    });
  } catch (e) {
    const hint = /handshake failed \((\d+)\)/.exec(e.message);
    let why = e.message;
    if (hint) {
      const code = hint[1];
      why = `دست‌دادن WebSocket رد شد با HTTP ${code}` + (
        code === '404' ? ' — مسیر به سرور رسید ولی شناخته نشد؛ UUID/مسیر کانفیگ با سرور فرق دارد (احتمالاً state عوض شده).' :
        code === '426' || code === '400' ? ' — یک پروکسی در مسیر Upgrade را نمی‌پذیرد.' :
        code === '502' || code === '503' || code === '504' ? ' — Worker/پروکسی هاست نتوانست به سرور وصل شود یا WebSocket را عبور نمی‌دهد.' :
        code === '403' ? ' — Cloudflare/هاست درخواست را بلاک کرد (WAF، Bot Fight Mode).' :
        code === '200' ? ' — به‌جای 101 یک صفحه‌ی معمولی برگشت؛ پروکسی هاست Upgrade را به درخواست عادی تبدیل می‌کند (WebSocket پشتیبانی نمی‌شود).' : '');
    } else if (/ENOTFOUND|EAI_AGAIN/.test(why)) why = `نام ${connHost} resolve نشد.`;
    else if (/ECONNREFUSED/.test(why)) why = `اتصال به ${where} رد شد.`;
    else if (/timeout/i.test(why)) why = `اتصال به ${where} زمانش تمام شد (بسته یا فیلتر).`;
    else if (/certificate|self signed|unable to verify/i.test(why)) why = `گواهی TLS نامعتبر: ${why}`;
    return { ok: false, text: `${external ? 'تست از بیرون' : 'تست داخلی'} ناموفق — ${why}` };
  }
  return new Promise((resolve) => {
    const header = useVless ? proxy.buildVlessHeader(target.hostname, port) : proxy.buildTrojanHeader(target.hostname, port);
    const httpReq = `GET ${target.pathname || '/'} HTTP/1.1\r\nHost: ${target.hostname}\r\nUser-Agent: v2gate-selftest\r\nConnection: close\r\n\r\n`;
    stream.write(Buffer.concat([header, Buffer.from(httpReq)]));
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => { stream.destroy(); resolve({ ok: false, text: 'پاسخی از مقصد نرسید (timeout ۱۰ ثانیه). خروجی سرور به اینترنت را بررسی کنید.' }); }, 10000);
    const finish = (r) => { clearTimeout(timer); stream.destroy(); resolve(r); };
    stream.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      let body = buf;
      if (useVless) {
        if (buf.length < 2) return;
        if (buf[0] !== 0) return finish({ ok: false, text: 'پاسخ VLESS نامعتبر بود.' });
        body = buf.subarray(2 + buf[1]);
      }
      const m = /^HTTP\/1\.[01] (\d{3})/.exec(body.toString('latin1'));
      if (m) {
        const ms = Date.now() - started;
        const ok = m[1][0] === '2' || m[1][0] === '3';
        finish({ ok, text: ok
          ? (external
            ? `موفق — از ${where} تا سرور، WebSocket و ${useVless ? 'VLESS' : 'Trojan'} کامل عبور کرد و ${target.hostname} پاسخ HTTP ${m[1]} داد (${ms}ms). کل زنجیره سالم است؛ اگر کلاینت وصل نمی‌شود، مشکل مسیر ISP شما تا Cloudflare است (IP تمیز).`
            : `موفق — ${useVless ? 'VLESS' : 'Trojan'} over WebSocket → ${target.hostname} پاسخ HTTP ${m[1]} داد (${ms}ms). موتور پروکسی سالم است.`)
          : `مقصد پاسخ HTTP ${m[1]} داد (${ms}ms).` });
      }
    });
    stream.on('error', (e) => finish({ ok: false, text: `خطا: ${e.message}` }));
    stream.on('close', () => { if (!buf.length) finish({ ok: false, text: 'اتصال بسته شد بدون پاسخ — احتمالاً سرور به مقصد دسترسی ندارد.' }); });
  });
}

// ---- panel ------------------------------------------------------------------------
function renderDashboard(req, res, notice, sq = '') {
  const reqAddr = requestAddress(req);
  const isLocal = /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(reqAddr.host);
  // Reached over https at the very host we advertise, yet configured as plain
  // http on a raw port → the configuration is certainly wrong; fix it in place.
  if (!isLocal && !settings.publicOverride && reqAddr.host && reqAddr.host === settings.host && reqAddr.host !== settings.publicIp &&
      reqAddr.tls === 'proxy' && settings.tlsMode === 'off' && settings.publicPort !== reqAddr.port) {
    setPublicOverride(reqAddr);
    qrCache.clear();
    log(`public address auto-corrected to ${reqAddr.host}:${reqAddr.port} (tls via proxy)`);
    notice = notice || { ok: true, text: `آدرس عمومی خودکار اصلاح شد: ${reqAddr.host}:${reqAddr.port} با TLS. کانفیگ‌ها و لینک سابسکریپشن تازه شدند — دوباره کپی کنید.` };
  }
  const mismatch = !isLocal && reqAddr.host && reqAddr.host !== settings.publicIp &&
    (reqAddr.host !== settings.host || reqAddr.port !== settings.publicPort ||
      (settings.tlsMode !== 'self' && reqAddr.tls !== settings.tlsMode));
  const configs = links.allConfigs();
  const subUrl = links.subscriptionUrl(baseUrl(req));
  const qrs = { __sub: qr(subUrl) };
  for (const c of configs) qrs[c.key] = qr(c.link);
  return send(
    res,
    200,
    panel.dashboard({
      panelPath: settings.panelPath,
      host: settings.host,
      publicPort: settings.publicPort,
      tlsMode: settings.tlsMode,
      publicOverride: settings.publicOverride,
      reqAddr,
      mismatch,
      stats: proxy.stats,
      xray: xray.status,
      configs,
      cleanIps: state.cleanIps || [],
      subUrl,
      uptime: uptimeString(),
      qrs,
      notice,
      sq,
      directAddr: settings.publicIp ? `${settings.publicIp}:${settings.directPort || settings.port}` : '',
    })
  );
}

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

  // Session: normally a cookie. Some Workers/host proxies drop cookies in one
  // direction, so the same signed token may also travel in the URL (?s=…); every
  // panel link/form then carries it along. The cookie path is preferred when it works.
  const cookies = parseCookies(req);
  const sParam = url.searchParams.get('s') || '';
  const authCookie = validSession(cookies[COOKIE]);
  const authUrl = !authCookie && validSession(sParam);
  const authed = authCookie || authUrl;
  const sq = authUrl ? `?s=${encodeURIComponent(sParam)}` : '';
  const fromLogin = url.searchParams.get('from') === 'login';

  if (sub === '/login' && req.method === 'POST') {
    if (!loginAllowed(ip)) {
      return send(res, 429, panel.loginPage({ action: `${p}/login`, error: 'تلاش‌های ناموفق زیاد. ۱۰ دقیقه بعد دوباره امتحان کنید.' }));
    }
    const form = parseForm(await readBody(req));
    if (verifyPassword(form.password || '', state.panelPasswordHash)) {
      failures.delete(ip);
      const token = makeSession();
      // A 200 page that navigates itself, not a 302: some proxies follow a redirect
      // server-side and drop the Set-Cookie of the 302 on the way. The token also
      // rides in the URL so the panel works even if the cookie never comes back.
      return send(res, 200, panel.loginOkPage({ next: `${p}?from=login&s=${encodeURIComponent(token)}` }), {
        'Set-Cookie': sessionCookie(req, token, SESSION_TTL / 1000),
      });
    }
    noteFailure(ip);
    return send(res, 401, panel.loginPage({ action: `${p}/login`, error: 'رمز عبور اشتباه است.' }));
  }

  if (!authed) {
    const hadAnyCookie = Boolean(req.headers.cookie);
    const error = !fromLogin ? undefined
      : cookies[COOKIE] || sParam
        ? 'نشست معتبر نیست — احتمالاً سرویس ری‌استارت شده و کلید نشست عوض شده. دوباره وارد شوید.'
        : 'رمز درست بود ولی نه کوکی رسید نه توکن. دوباره وارد شوید.';
    if (fromLogin) log(`login session missing: cookieHeader=${hadAnyCookie} s=${Boolean(sParam)} xfh=${req.headers['x-forwarded-host'] || '-'} xfp=${req.headers['x-forwarded-proto'] || '-'}`);
    return send(res, 200, panel.loginPage({ action: `${p}/login`, error }));
  }

  // Cookie works → drop the token from the URL for a clean address.
  if (fromLogin && authCookie) return redirect(res, p);

  // Clean-IP finder, server half: verify candidate edge IPs serve this panel.
  // GET /panel/scan?count=60            → random Cloudflare candidates
  // GET /panel/scan?ips=a,b,c           → verify a user-supplied list
  if (sub === '/scan') {
    if (!links.tlsOn() || net.isIP(settings.host)) {
      return send(res, 400, JSON.stringify({ error: 'اسکن فقط وقتی معنی دارد که سرویس پشت Cloudflare با دامنه و TLS باشد.' }), { 'Content-Type': 'application/json' });
    }
    const listParam = (url.searchParams.get('ips') || '').split(/[\s,;]+/).map((s) => s.trim()).filter(scan.isIPv4).slice(0, 200);
    const count = Math.min(200, Math.max(10, Number(url.searchParams.get('count')) || 60));
    const ips = listParam.length ? listParam : scan.candidates(count);
    const t0 = Date.now();
    const results = await scan.verifyMany(ips, { port: Number(process.env.SCAN_PORT) || settings.publicPort });
    const ok = results.filter((r) => r.ok).sort((a, b) => a.ms - b.ms);
    log(`scan: ${ok.length}/${results.length} candidates serve ${settings.host} (${Date.now() - t0}ms)`);
    return send(res, 200, JSON.stringify({ host: settings.host, tested: results.length, ok, failed: results.filter((r) => !r.ok).length }), { 'Content-Type': 'application/json' });
  }

  // Recent requests (diagnostics).
  if (sub === '/log') {
    return send(res, 200, JSON.stringify({ now: Date.now(), entries: reqlog.recent(150) }), { 'Content-Type': 'application/json' });
  }

  // Tiny probe used by the dashboard's cookie check (JS fetch).
  if (sub === '/echo') {
    return send(res, 200, JSON.stringify({
      cookieHeader: Boolean(req.headers.cookie),
      sessionCookie: Boolean(cookies[COOKIE]),
      probeCookie: Boolean(cookies.v2g_probe),
      xForwardedHost: req.headers['x-forwarded-host'] || null,
      xForwardedProto: req.headers['x-forwarded-proto'] || null,
    }), { 'Content-Type': 'application/json' });
  }

  const back = p + sq;
  if (req.method === 'POST') {
    if (sub === '/logout') {
      return send(res, 200, panel.loginOkPage({ next: p, text: 'خارج شدید.' }), { 'Set-Cookie': sessionCookie(req, '', 0) });
    }
    if (sub === '/rotate') {
      updateState({ uuid: crypto.randomUUID(), trojanPassword: randomToken(12), ssPassword: randomToken(12), subToken: randomToken(16) });
      qrCache.clear();
      log('credentials rotated');
      xray.restart().catch(() => {});
      return redirect(res, back);
    }
    if (sub === '/xray-restart') {
      await xray.restart();
      return redirect(res, back);
    }
    if (sub === '/usehost') {
      const a = requestAddress(req);
      setPublicOverride(a);
      qrCache.clear();
      log(`public address set from panel: ${a.host}:${a.port} tls=${a.tls}`);
      return redirect(res, back);
    }
    if (sub === '/clearhost') {
      setPublicOverride(null);
      qrCache.clear();
      log('public address override cleared — restart to re-apply env/auto-detected values');
      return renderDashboard(req, res, { ok: true, text: 'آدرس دستی پاک شد. برای اعمال مقادیر env/خودکار، سرویس را ری‌استارت کنید.' }, sq);
    }
    if (sub === '/cleanips') {
      const form = parseForm(await readBody(req));
      updateState({ cleanIps: parseCleanIps(form.ips) });
      log(`clean IPs updated (${state.cleanIps.length})`);
      return redirect(res, back);
    }
    if (sub === '/selftest') {
      const r = await selfTest('internal');
      log('self-test:', r.ok ? 'OK' : 'FAIL', '-', r.text);
      return renderDashboard(req, res, r, sq);
    }
    if (sub === '/extest') {
      const form = parseForm(await readBody(req));
      const addr = (form.address || '').trim().replace(/^https?:\/\//, '').split(/[/:]/)[0];
      const r = await selfTest('external', addr);
      log('external test:', r.ok ? 'OK' : 'FAIL', '-', r.text);
      return renderDashboard(req, res, r, sq);
    }
    return notFound(res);
  }

  if (sub === '/' || sub === '') {
    const notice = fromLogin && authUrl
      ? { ok: true, text: 'وارد شدید. کوکی نشست به سرور نرسید، پس نشست از طریق آدرس صفحه حفظ می‌شود — از همین دکمه‌ها و لینک‌های پنل استفاده کنید و آدرس را به کسی ندهید.' }
      : undefined;
    return renderDashboard(req, res, notice, sq);
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
  const filter = links.makeFilter({ only: url.searchParams.get('only'), exclude: url.searchParams.get('exclude') });
  const common = {
    'Profile-Title': /^[\x20-\x7e]+$/.test(settings.configName)
      ? settings.configName
      : 'base64:' + Buffer.from(settings.configName).toString('base64'),
    'Profile-Update-Interval': '12',
    'Subscription-Userinfo': 'upload=0; download=0; total=0; expire=0',
  };
  if (format === 'raw') {
    return send(res, 200, links.subscriptionRaw(filter), { ...common, 'Content-Type': 'text/plain; charset=utf-8' });
  }
  if (format === 'clash') {
    return send(res, 200, links.clashYaml(filter), {
      ...common,
      'Content-Type': 'text/yaml; charset=utf-8',
      'Content-Disposition': 'attachment; filename="v2gate.yaml"',
    });
  }
  return send(res, 200, links.subscriptionBase64(filter), { ...common, 'Content-Type': 'text/plain; charset=utf-8' });
}

// ---- HTTP request router -------------------------------------------------------------
async function onRequest(req, res) {
  const started = Date.now();
  res.on('finish', () => reqlog.add({
    kind: 'http', method: req.method, path: req.url, status: res.statusCode, ms: Date.now() - started,
    ip: clientIp(req), ua: reqlog.shortUa(req.headers['user-agent']),
    host: req.headers['x-forwarded-host'] || req.headers.host || '-',
  }));
  try {
    const url = new URL(req.url, 'http://localhost');
    const p = url.pathname;

    if (p === '/health' || p === '/healthz') {
      return send(res, 200, JSON.stringify({ ok: true, uptime: Date.now() - startedAt, active: proxy.stats.active, xhttpSessions: xhttp.sessionCount() }), {
        'Content-Type': 'application/json',
      });
    }
    if (p === settings.panelPath || p.startsWith(settings.panelPath + '/')) return await handlePanel(req, res, url);
    if (p.startsWith(settings.subPath + '/')) return handleSubscription(req, res, url);

    // XHTTP transport (plain HTTP, no Upgrade)
    if (xhttp.handleRequest(req, res, p, xhttpRoutes(), proxy.handle, (m) => plog(`${clientIp(req)} ${m}`))) return;

    // A proxy path hit without an Upgrade header (e.g. a scanner) → plain 404.
    if (routes().has(p) || xray.routes().has(p)) return notFound(res);

    if (p === '/') return send(res, 200, panel.decoyPage());
    return notFound(res);
  } catch (err) {
    log('request error', err.message);
    if (!res.headersSent) send(res, 500, '<h1>500</h1>');
  }
}

// ---- WebSocket / HTTPUpgrade → native proxy engine --------------------------------------
function onUpgrade(req, socket, head) {
  const pathname = req.url.split('?')[0];
  const route = routes().get(pathname);
  const logUp = (status, note) => reqlog.add({
    kind: 'upgrade', method: req.method, path: req.url, status, note,
    ip: clientIp(req), ua: reqlog.shortUa(req.headers['user-agent']),
    host: req.headers['x-forwarded-host'] || req.headers.host || '-',
  });
  if (!route) {
    const xrayPort = xray.routes().get(pathname);
    if (xrayPort) { logUp(101, 'xray'); return passThrough(req, socket, head, xrayPort); }
    logUp(404, 'unknown path');
    socket.end('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
    return;
  }
  logUp(101, `${route.protocol}/${route.transport}`);
  socket.setNoDelay(true);
  socket.setTimeout(settings.idleTimeout, () => socket.destroy());
  socket.on('error', () => {});

  const stream = route.transport === 'ws' ? ws.acceptWebSocket(req, socket, head) : ws.acceptHttpUpgrade(req, socket, head);
  if (!stream) return;
  const ip = clientIp(req);
  proxy.handle(stream, route.protocol, (msg) => plog(`${route.protocol}/${route.transport} ${ip} ${msg}`));
}

// Xray engine: replay the raw upgrade request to the matching loopback inbound
// and pipe the two sockets; Xray does its own WebSocket/HTTPUpgrade handshake.
function passThrough(req, socket, head, port) {
  const upstream = net.connect({ host: '127.0.0.1', port });
  socket.setNoDelay(true);
  socket.setTimeout(settings.idleTimeout, () => socket.destroy());
  upstream.setNoDelay(true);
  const cleanup = () => { socket.destroy(); upstream.destroy(); };
  upstream.on('connect', () => {
    let raw = `${req.method} ${req.url} HTTP/${req.httpVersion}\r\n`;
    for (let i = 0; i < req.rawHeaders.length; i += 2) raw += `${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}\r\n`;
    upstream.write(raw + '\r\n');
    if (head && head.length) upstream.write(head);
    socket.pipe(upstream);
    upstream.pipe(socket);
  });
  upstream.on('error', cleanup);
  socket.on('error', cleanup);
  upstream.on('close', () => socket.destroy());
  socket.on('close', () => upstream.destroy());
}

// ---- TLS (self-signed, generated in pure Node) --------------------------------------------
function loadOrCreateSelfSignedCert() {
  const certFile = path.join(settings.dataDir, 'cert.pem');
  const keyFile = path.join(settings.dataDir, 'key.pem');
  const wantNames = [settings.host, settings.publicIp].filter(Boolean);
  if (fs.existsSync(certFile) && fs.existsSync(keyFile)) {
    try {
      const x = new crypto.X509Certificate(fs.readFileSync(certFile));
      const san = x.subjectAltName || '';
      const covers = wantNames.every((n) => san.includes(n));
      if (covers && new Date(x.validTo).getTime() - Date.now() > 7 * 86400 * 1000) {
        return { cert: fs.readFileSync(certFile), key: fs.readFileSync(keyFile) };
      }
      log(covers ? 'TLS certificate expiring soon, regenerating' : 'TLS certificate does not cover the current host/IP, regenerating');
    } catch (e) {
      log('stored certificate unreadable, regenerating:', e.message);
    }
  }
  const { cert, key } = certgen.generate({ commonName: settings.host, altNames: wantNames, days: 825 });
  fs.writeFileSync(certFile, cert);
  fs.writeFileSync(keyFile, key, { mode: 0o600 });
  log(`generated self-signed certificate for ${wantNames.join(', ')}`);
  return { cert, key };
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
async function main() {
  log(`starting on port ${settings.port} (tls mode: ${settings.tlsMode}${settings.onPaaS ? ', PaaS detected' : ''})`);

  // Public IP is needed for direct/Reality links even when HOST is a (CDN) domain.
  const ip = settings.publicIpEnv || (net.isIP(settings.host) ? settings.host : await discoverHost());
  settings.publicIp = ip || '';
  if (!settings.host) {
    settings.host = ip || '127.0.0.1';
    log(`public host not set; using ${settings.host}${ip ? '' : ' (could not detect public IP — set HOST)'}`);
  } else if (ip) log(`public IP ${ip}`);

  // Plain HTTP server (behind a Worker / host proxy) and, when a certificate can be
  // made, an HTTPS server for direct IP:port connections. Neither listens itself:
  // a protocol-sniffing listener (mux.js) hands each connection to the right one.
  const tune = (s) => { s.on('upgrade', onUpgrade); s.keepAliveTimeout = 65000; s.headersTimeout = 70000; s.requestTimeout = 0; return s; };
  const httpServer = tune(http.createServer(onRequest));
  let httpsServer = null;
  try {
    httpsServer = tune(https.createServer(loadOrCreateSelfSignedCert(), onRequest));
    settings.directTls = true;
  } catch (e) {
    settings.directTls = false;
    if (settings.tlsMode === 'self') throw e;
    log(`direct TLS unavailable (${e.message.split('(')[0].trim()}); direct configs disabled`);
  }

  // The HTTPS server listens on a loopback port; the mux splices TLS connections into it.
  let httpsPort = null;
  if (httpsServer) {
    await new Promise((resolve) => httpsServer.listen(0, '127.0.0.1', resolve));
    httpsPort = httpsServer.address().port;
  }
  const realityTarget = () => (xray.status.reality.active ? { port: xray.status.reality.loopPort, sni: xray.realitySni() } : null);
  const muxes = [];
  const listenMux = (port, label) => new Promise((resolve) => {
    const m = mux.createMux({ httpServer, httpsPort, reality: realityTarget, log,
      onDecision: (d) => reqlog.add({ kind: 'tcp', method: '-', path: `:${port}`, status: d.kind === 'dropped' ? 'RST' : d.kind === 'empty' ? '—' : 'OK', note: d.note, ip: d.ip, ua: '-', host: d.sni || '-' }) });
    m.on('error', (e) => { log(`${label} listener on :${port} failed: ${e.message}`); resolve(false); });
    m.listen(port, '0.0.0.0', () => { muxes.push(m); log(`${label} listening on 0.0.0.0:${port} (http${httpsServer ? ' + https' : ''}${settings.enable.reality !== false ? ' + reality' : ''})`); resolve(true); });
  });
  await listenMux(settings.port, 'main');
  log(`panel: ${settings.panelPath}   subscription: ${settings.subPath}/<token>`);
  log(`routes: ${[...routes().entries()].map(([k, v]) => `${k} (${v.protocol}/${v.transport})`).join(', ')}` +
    `${xhttpRoutes().size ? ', ' + [...xhttpRoutes().entries()].map(([k, v]) => `${k} (${v}/xhttp)`).join(', ') : ''}`);
  log(`clients connect to ${settings.host}:${settings.publicPort} ${links.tlsOn() ? 'with' : 'without'} TLS` +
    (settings.publicIp && settings.directTls ? `; direct: ${settings.publicIp}:${settings.directPort || settings.port}` : ''));

  // Optional Xray engine (VMess/SS/Reality) boots in the background so the panel is up
  // immediately. A second public listener on REALITY_PORT (e.g. 443) is added when free.
  xray.boot().then(async () => {
    const r = xray.status.reality;
    if (r.active && r.extraPort) {
      const ok = await listenMux(r.extraPort, 'reality');
      if (!ok) r.extraPort = null;
    }
  });

  const shutdown = (sig) => {
    log(`${sig} received, shutting down`);
    for (const m of muxes) m.close();
    xray.stop().finally(() => process.exit(0));
    setTimeout(() => process.exit(0), 3000).unref();
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main().catch((err) => {
  console.error('[v2gate] fatal:', err);
  process.exit(1);
});
