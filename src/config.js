'use strict';
// Loads environment variables (+ optional .env file) and the persisted state
// (UUID, trojan password, panel password hash, subscription token, clean IPs).

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..');

// ---- tiny .env loader (no dependency) --------------------------------------
function loadDotEnv() {
  const file = path.join(ROOT, '.env');
  if (!fs.existsSync(file)) return;
  for (const raw of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    let val = line.slice(eq + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    } else {
      val = val.replace(/\s+#.*$/, '').trim(); // allow "KEY=value  # comment"
    }
    if (process.env[key] === undefined) process.env[key] = val;
  }
}
loadDotEnv();

const env = (k, d) => (process.env[k] !== undefined && process.env[k] !== '' ? process.env[k] : d);
const bool = (k, d) => {
  const v = env(k);
  if (v === undefined) return d;
  return !['0', 'false', 'no', 'off'].includes(String(v).toLowerCase());
};

// ---- detect platform --------------------------------------------------------
// PaaS hosts (Render, Railway, Koyeb, Fly, Heroku…) terminate TLS for us and
// forward plain HTTP to our port. In that case the client connects to :443 with
// TLS, so the generated configs should say so.
function detectPlatformHost() {
  if (process.env.RENDER_EXTERNAL_HOSTNAME) return process.env.RENDER_EXTERNAL_HOSTNAME;
  if (process.env.RAILWAY_PUBLIC_DOMAIN) return process.env.RAILWAY_PUBLIC_DOMAIN;
  if (process.env.KOYEB_PUBLIC_DOMAIN) return process.env.KOYEB_PUBLIC_DOMAIN;
  if (process.env.FLY_APP_NAME) return `${process.env.FLY_APP_NAME}.fly.dev`;
  return null;
}
const platformHost = detectPlatformHost();
const onPaaS = Boolean(platformHost);

const DATA_DIR = path.resolve(ROOT, env('DATA_DIR', 'data'));
fs.mkdirSync(DATA_DIR, { recursive: true });

// People paste "https://my.host/" or "my.host:8443" into HOST — accept all of
// those and pull out just the hostname (and the port, if one was given).
// "https://my.host/" also tells us the public side is TLS on 443.
function parseHostInput(raw) {
  let s = String(raw || '').trim();
  if (!s) return { host: '', port: null, https: null };
  const hasScheme = /^[a-z]+:\/\//i.test(s);
  if (!hasScheme) s = 'http://' + s;
  try {
    const u = new URL(s);
    const host = u.hostname.replace(/^\[|\]$/g, '');
    const port = u.port ? Number(u.port) : null;
    const https = hasScheme ? u.protocol === 'https:' : null;
    return { host, port, https };
  } catch {
    return { host: String(raw).trim().replace(/^https?:\/\//i, '').split(/[/:?#]/)[0], port: null, https: null };
  }
}

const hostEnv = parseHostInput(env('HOST', platformHost || ''));
const localPort = Number(env('PORT', env('SERVER_PORT', 3000)));
const tlsEnv = env('TLS_MODE', onPaaS || hostEnv.https === true ? 'proxy' : 'off');
const defaultPublicPort = onPaaS || tlsEnv === 'proxy' ? 443 : localPort;

// ---- static settings ----------------------------------------------------------
const settings = {
  root: ROOT,
  dataDir: DATA_DIR,

  // The single public port the host gives us.
  port: localPort,

  // Public hostname clients should connect to (also the TLS SNI / Host header).
  // Auto-detected on PaaS, otherwise resolved from the public IP at startup.
  host: hostEnv.host,
  // Public port clients connect to (443 on PaaS/behind a TLS proxy, otherwise `port`).
  publicPort: Number(env('PUBLIC_PORT', hostEnv.port || defaultPublicPort)),

  // TLS mode:
  //   proxy → host/Cloudflare terminates TLS. We serve plain HTTP.
  //   self  → we serve HTTPS with a self-signed cert (VPS / raw port).
  //   off   → plain HTTP, configs without TLS.
  tlsMode: tlsEnv,

  // True when host/port/tls came from the panel's "use this address" button.
  publicOverride: false,

  panelPath: '/' + env('PANEL_PATH', 'panel').replace(/^\/+|\/+$/g, ''),
  subPath: '/' + env('SUB_PATH', 'sub').replace(/^\/+|\/+$/g, ''),

  enable: {
    vlessWs: bool('ENABLE_VLESS_WS', true),
    trojanWs: bool('ENABLE_TROJAN_WS', true),
    vlessHu: bool('ENABLE_VLESS_HTTPUPGRADE', true),
    trojanHu: bool('ENABLE_TROJAN_HTTPUPGRADE', false),
    vlessXh: bool('ENABLE_VLESS_XHTTP', true),
    trojanXh: bool('ENABLE_TROJAN_XHTTP', false),
    // Served by the optional Xray engine (src/xray.js)
    xray: bool('ENABLE_XRAY', true),
    vmessWs: bool('ENABLE_VMESS_WS', true),
    vmessHu: bool('ENABLE_VMESS_HTTPUPGRADE', true),
    ssWs: bool('ENABLE_SS_WS', true),
    // VLESS + Reality: a direct TCP listener (VPS only). 'auto' = on when the
    // port is free and we're not on a PaaS; true/false force it.
    reality: (() => { const v = String(env('ENABLE_REALITY', 'auto')).toLowerCase(); return v === 'auto' ? 'auto' : !['0', 'false', 'no', 'off'].includes(v); })(),
  },

  // Reality (needs a real public IP; the port must be reachable from the internet)
  // Extra public listener for Reality (e.g. 443 on a VPS). 0 = main port only, which is
  // the safe default for containers that expose a single port.
  realityPort: Number(env('REALITY_PORT', 0)),
  realityDest: env('REALITY_DEST', 'dl.google.com:443'),     // camouflage site (must support TLS 1.3 + h2)
  realitySni: env('REALITY_SNI', ''),                        // defaults to the host part of REALITY_DEST
  realityAddress: env('REALITY_ADDRESS', ''),                // address in the share link; defaults to the public IP
  publicIp: '',                                              // discovered at startup
  publicIpEnv: env('PUBLIC_IP', ''),                         // override auto-detection
  directTls: false,                                          // set at startup when a self-signed cert exists

  // Direct configs: clients connect straight to the public IP:port (no CDN) with
  // self-signed TLS. 'auto' = on when a public IP and a certificate are available.
  direct: (() => { const v = String(env('ENABLE_DIRECT', 'auto')).toLowerCase(); return v === 'auto' ? 'auto' : !['0', 'false', 'no', 'off'].includes(v); })(),
  directPort: Number(env('DIRECT_PORT', 0)) || null,         // public port if it differs from PORT (NAT / container mapping)
  directSni: env('DIRECT_SNI', ''),                          // SNI in direct links; defaults to HOST (any name works: cert is self-signed)
  // Direct configs WITHOUT TLS (plain WebSocket/XHTTP to IP:port). Needed when an HTTP-only
  // proxy sits in front of the port. 'auto' = on when a public IP is known.
  directPlain: (() => { const v = String(env('ENABLE_DIRECT_PLAIN', 'auto')).toLowerCase(); return v === 'auto' ? 'auto' : !['0', 'false', 'no', 'off'].includes(v); })(),

  // Xray engine
  binDir: path.resolve(ROOT, env('BIN_DIR', 'bin')),
  xrayVersion: env('XRAY_VERSION', 'latest'),
  xrayBasePort: Number(env('XRAY_BASE_PORT', 10100)),
  xrayLogLevel: env('XRAY_LOG_LEVEL', 'warning'),
  ssMethod: env('SS_METHOD', 'aes-128-gcm'),

  configName: env('CONFIG_NAME', 'V2Gate'),

  // Proxy engine
  // Client DNS (UDP inside the tunnel): DoH by default (works where outbound :53 is blocked).
  // Set DNS_DOH= (empty) to fall back to TCP DNS_RESOLVER:53.
  dohUrl: env('DNS_DOH', 'https://1.1.1.1/dns-query'),
  dnsResolver: env('DNS_RESOLVER', '8.8.8.8'),
  // Full UDP relay (QUIC, games, VoIP). Off → only DNS is relayed.
  udpRelay: bool('UDP_RELAY', true),
  dnsResolverPort: Number(env('DNS_RESOLVER_PORT', 53)),
  idleTimeout: Number(env('IDLE_TIMEOUT', 300)) * 1000,
  blockPrivate: bool('BLOCK_PRIVATE', true),

  // Comma-separated clean IPs/hosts to seed the list (editable in the panel).
  cleanIpsEnv: env('CLEAN_IPS', ''),

  onPaaS,
};

// ---- persisted state -----------------------------------------------------------
const STATE_FILE = path.join(DATA_DIR, 'state.json');

function readState() {
  try {
    return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
  } catch {
    return {};
  }
}

function writeState(state) {
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2), { mode: 0o600 });
}

function sha256(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 32).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored) return false;
  const [salt, hash] = stored.split(':');
  if (!salt || !hash) return false;
  const candidate = crypto.scryptSync(password, salt, 32);
  const expected = Buffer.from(hash, 'hex');
  return candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected);
}

function randomToken(bytes = 16) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function parseCleanIps(text) {
  return [...new Set(
    String(text || '')
      .split(/[\s,;]+/)
      .map((s) => s.trim())
      .filter((s) => s && /^[A-Za-z0-9.:\-\[\]]+$/.test(s))
  )].slice(0, 50);
}

function ensureState() {
  const state = readState();
  let changed = false;

  // Environment overrides win, then stored values, then generated.
  // A non-UUID value (e.g. a random string generated by the host) is mapped to a
  // proper UUID deterministically so the same env value always yields the same id.
  let uuid = env('UUID');
  if (uuid && !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(uuid)) {
    const h = sha256('v2gate:' + uuid);
    uuid = `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-${((parseInt(h[16], 16) & 0x3) | 0x8).toString(16)}${h.slice(17, 20)}-${h.slice(20, 32)}`;
  } else if (uuid) {
    uuid = uuid.toLowerCase();
  }
  if (uuid) {
    if (state.uuid !== uuid) { state.uuid = uuid; changed = true; }
  } else if (!state.uuid) {
    state.uuid = crypto.randomUUID();
    changed = true;
  }

  const trojanPassword = env('TROJAN_PASSWORD');
  if (trojanPassword) {
    if (state.trojanPassword !== trojanPassword) { state.trojanPassword = trojanPassword; changed = true; }
  } else if (!state.trojanPassword) {
    state.trojanPassword = randomToken(12);
    changed = true;
  }

  const ssPassword = env('SS_PASSWORD');
  if (ssPassword) {
    if (state.ssPassword !== ssPassword) { state.ssPassword = ssPassword; changed = true; }
  } else if (!state.ssPassword) {
    state.ssPassword = randomToken(12);
    changed = true;
  }

  const subToken = env('SUB_TOKEN');
  if (subToken) {
    if (state.subToken !== subToken) { state.subToken = subToken; changed = true; }
  } else if (!state.subToken) {
    state.subToken = randomToken(16);
    changed = true;
  }

  const panelPassword = env('PANEL_PASSWORD');
  if (panelPassword && !verifyPassword(panelPassword, state.panelPasswordHash)) {
    state.panelPasswordHash = hashPassword(panelPassword);
    changed = true;
  }

  if (!state.realityShortId) {
    state.realityShortId = crypto.randomBytes(4).toString('hex');
    changed = true;
  }

  if (!state.sessionSecret) {
    state.sessionSecret = randomToken(32);
    changed = true;
  }

  if (!Array.isArray(state.cleanIps)) {
    state.cleanIps = parseCleanIps(settings.cleanIpsEnv);
    changed = true;
  } else if (settings.cleanIpsEnv && !state.cleanIpsSeededFromEnv) {
    state.cleanIps = [...new Set([...state.cleanIps, ...parseCleanIps(settings.cleanIpsEnv)])];
    state.cleanIpsSeededFromEnv = true;
    changed = true;
  }

  if (changed) writeState(state);
  return state;
}

const state = ensureState();

function updateState(patch) {
  Object.assign(state, patch);
  writeState(state);
  return state;
}

// A public address saved from the panel beats env/auto-detection (TLS 'self' is
// a server mode and can't be switched live, so it is never overridden).
function applyPublicOverride() {
  const o = state.publicOverride;
  if (!o || !o.host) { settings.publicOverride = false; return; }
  settings.host = o.host;
  settings.publicPort = Number(o.port) || 443;
  if (settings.tlsMode !== 'self') settings.tlsMode = o.tls === 'proxy' ? 'proxy' : 'off';
  settings.publicOverride = true;
}
applyPublicOverride();

function setPublicOverride(o) {
  updateState({ publicOverride: o ? { host: parseHostInput(o.host).host, port: Number(o.port) || 443, tls: o.tls } : null });
  applyPublicOverride();
}

// Transport paths — derived from the UUID so they are not guessable by scanners.
function paths() {
  const tag = state.uuid.replace(/-/g, '').slice(0, 8);
  return {
    vlessWs: env('PATH_VLESS_WS', `/vless-${tag}`),
    trojanWs: env('PATH_TROJAN_WS', `/trojan-${tag}`),
    vlessHu: env('PATH_VLESS_HU', `/hu-${tag}`),
    trojanHu: env('PATH_TROJAN_HU', `/thu-${tag}`),
    vlessXh: env('PATH_VLESS_XHTTP', `/xh-${tag}`),
    trojanXh: env('PATH_TROJAN_XHTTP', `/txh-${tag}`),
    vmessWs: env('PATH_VMESS_WS', `/vmess-${tag}`),
    vmessHu: env('PATH_VMESS_HU', `/vmhu-${tag}`),
    ssWs: env('PATH_SS_WS', `/ss-${tag}`),
  };
}

// XHTTP is plain HTTP (no Upgrade): Map<basePath, protocol>
function xhttpRoutes() {
  const p = paths();
  const map = new Map();
  if (settings.enable.vlessXh) map.set(p.vlessXh, 'vless');
  if (settings.enable.trojanXh) map.set(p.trojanXh, 'trojan');
  return map;
}

// Map of URL path → { protocol, transport }
function routes() {
  const p = paths();
  const map = new Map();
  if (settings.enable.vlessWs) map.set(p.vlessWs, { protocol: 'vless', transport: 'ws' });
  if (settings.enable.trojanWs) map.set(p.trojanWs, { protocol: 'trojan', transport: 'ws' });
  if (settings.enable.vlessHu) map.set(p.vlessHu, { protocol: 'vless', transport: 'httpupgrade' });
  if (settings.enable.trojanHu) map.set(p.trojanHu, { protocol: 'trojan', transport: 'httpupgrade' });
  return map;
}

module.exports = {
  settings,
  state,
  updateState,
  setPublicOverride,
  parseHostInput,
  paths,
  routes,
  xhttpRoutes,
  parseCleanIps,
  sha256,
  hashPassword,
  verifyPassword,
  randomToken,
};
