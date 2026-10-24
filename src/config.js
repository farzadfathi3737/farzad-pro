'use strict';
// Loads environment variables (+ optional .env file) and the persisted state
// (UUID, trojan password, panel password hash, subscription token, TLS cert).

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

// ---- static settings ----------------------------------------------------------
const settings = {
  root: ROOT,
  dataDir: DATA_DIR,
  binDir: path.resolve(ROOT, env('BIN_DIR', 'bin')),

  // The single public port the host gives us.
  port: Number(env('PORT', env('SERVER_PORT', 3000))),

  // Public hostname/IP clients should connect to. Auto-detected on PaaS,
  // otherwise resolved from the public IP at startup if not set.
  host: env('HOST', platformHost || ''),
  // Public port clients connect to (443 on PaaS, otherwise the same as `port`).
  publicPort: Number(env('PUBLIC_PORT', onPaaS ? 443 : env('PORT', env('SERVER_PORT', 3000)))),

  // TLS mode:
  //   proxy → host terminates TLS (Render/Railway/Koyeb/Cloudflare). We serve plain HTTP.
  //   self  → we serve HTTPS with a self-signed cert (VPS / Pterodactyl with a raw port).
  //   off   → plain HTTP, configs without TLS.
  tlsMode: env('TLS_MODE', onPaaS ? 'proxy' : 'off'),

  // Panel path and subscription path prefix.
  panelPath: '/' + env('PANEL_PATH', 'panel').replace(/^\/+|\/+$/g, ''),
  subPath: '/' + env('SUB_PATH', 'sub').replace(/^\/+|\/+$/g, ''),

  // Which protocols to enable.
  enable: {
    vlessWs: bool('ENABLE_VLESS_WS', true),
    vmessWs: bool('ENABLE_VMESS_WS', true),
    trojanWs: bool('ENABLE_TROJAN_WS', true),
    vlessHttpUpgrade: bool('ENABLE_VLESS_HTTPUPGRADE', true),
  },

  // Name prefix for configs as shown in the client app.
  configName: env('CONFIG_NAME', 'V2Gate'),

  // Xray
  xrayVersion: env('XRAY_VERSION', 'latest'),
  xrayBasePort: Number(env('XRAY_BASE_PORT', 10100)),
  xrayLogLevel: env('XRAY_LOG_LEVEL', 'warning'),

  // Block private/LAN destinations through the proxy (recommended).
  blockPrivate: bool('BLOCK_PRIVATE', true),

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

  const subToken = env('SUB_TOKEN');
  if (subToken) {
    if (state.subToken !== subToken) { state.subToken = subToken; changed = true; }
  } else if (!state.subToken) {
    state.subToken = randomToken(16);
    changed = true;
  }

  const panelPassword = env('PANEL_PASSWORD');
  if (panelPassword) {
    // Re-hash only if the env password changed.
    if (!verifyPassword(panelPassword, state.panelPasswordHash)) {
      state.panelPasswordHash = hashPassword(panelPassword);
      changed = true;
    }
  }

  if (!state.sessionSecret) {
    state.sessionSecret = randomToken(32);
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

// Websocket paths — derived from the UUID so they are not guessable by scanners.
function paths() {
  const tag = state.uuid.replace(/-/g, '').slice(0, 8);
  return {
    vlessWs: env('PATH_VLESS_WS', `/vless-${tag}`),
    vmessWs: env('PATH_VMESS_WS', `/vmess-${tag}`),
    trojanWs: env('PATH_TROJAN_WS', `/trojan-${tag}`),
    vlessHttpUpgrade: env('PATH_VLESS_HU', `/hu-${tag}`),
  };
}

module.exports = {
  settings,
  state,
  updateState,
  paths,
  sha256,
  hashPassword,
  verifyPassword,
  randomToken,
};
