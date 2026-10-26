'use strict';
// Optional Xray-core engine, running *beside* the native engine for the
// protocols Node doesn't implement itself: VMess (WS / HTTPUpgrade) and
// Shadowsocks over WebSocket. Xray listens on 127.0.0.1 only; index.js routes
// its paths to it by raw TCP pass-through on the single public port.
//
// Everything here is best-effort: if the binary can't be downloaded or Xray
// won't start, the service keeps running with the native protocols only.

const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');
const https = require('https');
const { spawn, execFile } = require('child_process');
const zip = require('./zip');
const { settings, state, paths, updateState } = require('./config');

const BIN_DIR = settings.binDir;
const XRAY_BIN = path.join(BIN_DIR, process.platform === 'win32' ? 'xray.exe' : 'xray');
const CONFIG_FILE = path.join(settings.dataDir, 'xray.json');

const log = (...a) => console.log('[xray]', ...a);

// status.phase: disabled | downloading | starting | running | stopped | failed
const status = {
  phase: settings.enable.xray ? 'starting' : 'disabled', pid: null, startedAt: null, error: null, version: null,
  // loopPort: where Xray listens (127.0.0.1); port: public port for share links;
  // extraPort: an additional public listener (REALITY_PORT) when it is free.
  reality: { active: false, loopPort: null, port: null, extraPort: null, reason: null },
};

// ---- download ------------------------------------------------------------------
function assetName() {
  const platform = process.platform;
  const arch = os.arch();
  if (platform === 'linux') {
    if (arch === 'x64') return 'Xray-linux-64.zip';
    if (arch === 'arm64') return 'Xray-linux-arm64-v8a.zip';
    if (arch === 'arm') return 'Xray-linux-arm32-v7a.zip';
    if (arch === 'ia32') return 'Xray-linux-32.zip';
  }
  if (platform === 'darwin') return arch === 'arm64' ? 'Xray-macos-arm64-v8a.zip' : 'Xray-macos-64.zip';
  if (platform === 'win32') return arch === 'x64' ? 'Xray-windows-64.zip' : 'Xray-windows-32.zip';
  throw new Error(`unsupported platform ${platform}/${arch}`);
}

function downloadUrl() {
  const v = settings.xrayVersion;
  const base = 'https://github.com/XTLS/Xray-core/releases';
  return v === 'latest'
    ? `${base}/latest/download/${assetName()}`
    : `${base}/download/${v.startsWith('v') ? v : 'v' + v}/${assetName()}`;
}

function fetchBuffer(url, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > 8) return reject(new Error('too many redirects'));
    const req = https.get(url, { headers: { 'User-Agent': 'v2gate' }, timeout: 20000 }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        return resolve(fetchBuffer(new URL(res.headers.location, url).toString(), redirects + 1));
      }
      if (res.statusCode !== 200) { res.resume(); return reject(new Error(`HTTP ${res.statusCode}`)); }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('download timeout')));
  });
}

async function ensureBinary() {
  if (fs.existsSync(XRAY_BIN)) return XRAY_BIN;
  fs.mkdirSync(BIN_DIR, { recursive: true });
  const url = downloadUrl();
  status.phase = 'downloading';
  log('downloading', url);
  const buf = await fetchBuffer(url);
  const entryName = process.platform === 'win32' ? 'xray.exe' : 'xray';
  const files = zip.extract(buf, [entryName, 'geoip.dat', 'geosite.dat']);
  const bin = files.get(entryName);
  if (!bin) throw new Error('xray binary not found in archive');
  fs.writeFileSync(XRAY_BIN, bin);
  for (const extra of ['geoip.dat', 'geosite.dat']) if (files.has(extra)) fs.writeFileSync(path.join(BIN_DIR, extra), files.get(extra));
  if (process.platform !== 'win32') fs.chmodSync(XRAY_BIN, 0o755);
  log('installed', XRAY_BIN);
  return XRAY_BIN;
}

// ---- inbounds / config -------------------------------------------------------------
// Each protocol gets its own loopback port; index.js forwards by URL path.
function inbounds() {
  const p = paths();
  const base = settings.xrayBasePort;
  const sniff = { enabled: true, destOverride: ['http', 'tls', 'quic'] };
  const list = [];
  if (settings.enable.vmessWs) {
    list.push({ key: 'vmessWs', path: p.vmessWs, port: base, inbound: {
      tag: 'vmess-ws', listen: '127.0.0.1', port: base, protocol: 'vmess',
      settings: { clients: [{ id: state.uuid, level: 0 }] },
      streamSettings: { network: 'ws', security: 'none', wsSettings: { path: p.vmessWs } }, sniffing: sniff } });
  }
  if (settings.enable.vmessHu) {
    list.push({ key: 'vmessHu', path: p.vmessHu, port: base + 1, inbound: {
      tag: 'vmess-hu', listen: '127.0.0.1', port: base + 1, protocol: 'vmess',
      settings: { clients: [{ id: state.uuid, level: 0 }] },
      streamSettings: { network: 'httpupgrade', security: 'none', httpupgradeSettings: { path: p.vmessHu } }, sniffing: sniff } });
  }
  if (settings.enable.ssWs) {
    list.push({ key: 'ssWs', path: p.ssWs, port: base + 2, inbound: {
      tag: 'ss-ws', listen: '127.0.0.1', port: base + 2, protocol: 'shadowsocks',
      settings: { method: settings.ssMethod, password: state.ssPassword, network: 'tcp,udp' },
      streamSettings: { network: 'ws', security: 'none', wsSettings: { path: p.ssWs } }, sniffing: sniff } });
  }
  // Reality is a direct public listener — not routed through the Node server.
  if (status.reality.active && state.realityPrivateKey) {
    const sni = realitySni();
    list.push({ key: 'reality', path: null, port: status.reality.loopPort, direct: true, inbound: {
      tag: 'vless-reality', listen: '127.0.0.1', port: status.reality.loopPort, protocol: 'vless',
      settings: { clients: [{ id: state.uuid, flow: 'xtls-rprx-vision', level: 0 }], decryption: 'none' },
      streamSettings: {
        network: 'tcp', security: 'reality',
        realitySettings: { show: false, dest: settings.realityDest, xver: 0, serverNames: [sni], privateKey: state.realityPrivateKey, shortIds: [state.realityShortId, ''] },
      },
      sniffing: sniff } });
  }
  return list;
}

function realitySni() {
  return settings.realitySni || settings.realityDest.split(':')[0];
}

// ---- Reality helpers -------------------------------------------------------------
function portFree(port) {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(false));
    s.listen(port, '0.0.0.0', () => s.close(() => resolve(true)));
  });
}

function genX25519() {
  return new Promise((resolve, reject) => {
    execFile(XRAY_BIN, ['x25519'], { timeout: 10000 }, (err, out) => {
      if (err) return reject(err);
      // Xray prints "Private key: …" + "Public key: …" (older) or "PrivateKey: …" + "Password: …" (newer).
      const priv = /Private ?key:\s*(\S+)/i.exec(out);
      const pub = /(?:Public ?key|Password):\s*(\S+)/i.exec(out);
      if (!priv || !pub) return reject(new Error('could not parse x25519 output'));
      resolve({ privateKey: priv[1], publicKey: pub[1] });
    });
  });
}

async function prepareReality() {
  const prevExtra = status.reality.extraPort;
  status.reality = { active: false, loopPort: null, port: null, extraPort: null, reason: null };
  const want = settings.enable.reality;
  if (want === false) { status.reality.reason = 'disabled'; return; }
  if (want === 'auto' && settings.onPaaS) { status.reality.reason = 'PaaS host: no direct public port'; return; }
  if (!settings.publicIp) { status.reality.reason = 'public IP unknown (set REALITY_ADDRESS)'; return; }
  if (!state.realityPrivateKey || !state.realityPublicKey) {
    const keys = await genX25519();
    updateState({ realityPrivateKey: keys.privateKey, realityPublicKey: keys.publicKey });
    log('generated Reality key pair');
  }
  const loopPort = settings.xrayBasePort + 3;
  // Reality is reachable through the main port (mux sniffs the SNI) and, when free,
  // also directly on REALITY_PORT (443 by default) via a second mux listener.
  let extraPort = null;
  if (settings.realityPort && settings.realityPort !== settings.port) {
    if (prevExtra === settings.realityPort || await portFree(settings.realityPort)) extraPort = settings.realityPort;
    else log(`REALITY_PORT ${settings.realityPort} is in use; Reality stays on the main port only`);
  }
  status.reality = { active: true, loopPort, port: extraPort || settings.directPort || settings.port, extraPort, reason: null };
}

function buildConfig() {
  const rules = settings.blockPrivate ? [{ type: 'field', ip: ['geoip:private'], outboundTag: 'block' }] : [];
  return {
    log: { loglevel: settings.xrayLogLevel },
    inbounds: inbounds().map((x) => x.inbound),
    outbounds: [
      { tag: 'direct', protocol: 'freedom', settings: { domainStrategy: 'UseIP' } },
      { tag: 'block', protocol: 'blackhole' },
    ],
    routing: { domainStrategy: 'AsIs', rules },
  };
}

/** Map<path, loopbackPort> for the reverse proxy. Empty unless Xray is running. */
function routes() {
  const map = new Map();
  if (status.phase !== 'running') return map;
  for (const x of inbounds()) if (x.path) map.set(x.path, x.port);
  return map;
}

// ---- process -----------------------------------------------------------------------
let child = null;
let stopping = false;
let restarts = 0;

function spawnXray() {
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(buildConfig(), null, 2));
  stopping = false;
  child = spawn(XRAY_BIN, ['run', '-config', CONFIG_FILE], {
    env: { ...process.env, XRAY_LOCATION_ASSET: BIN_DIR },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  status.phase = 'running';
  status.pid = child.pid;
  status.startedAt = Date.now();
  status.error = null;
  log('started pid', child.pid, '·', inbounds().map((x) => `${x.inbound.protocol}/${x.inbound.streamSettings.security === 'reality' ? 'reality' : x.inbound.streamSettings.network}@${x.port}`).join(' '));
  child.stdout.on('data', (d) => process.stdout.write('[xray] ' + d));
  child.stderr.on('data', (d) => process.stderr.write('[xray] ' + d));
  child.on('error', (e) => { status.phase = 'failed'; status.error = e.message; log('spawn error', e.message); });
  child.on('exit', (code, signal) => {
    child = null;
    status.pid = null;
    if (stopping) { status.phase = 'stopped'; return; }
    restarts += 1;
    if (restarts > 8) { status.phase = 'failed'; status.error = `exited ${restarts} times (last code ${code})`; log('giving up after repeated exits'); return; }
    const delay = Math.min(30000, 1000 * 2 ** Math.min(restarts, 5));
    status.phase = 'starting';
    log(`exited (code=${code} signal=${signal}); restart in ${delay}ms`);
    setTimeout(spawnXray, delay);
  });
}

function stop() {
  return new Promise((resolve) => {
    stopping = true;
    if (!child) return resolve();
    const c = child;
    const t = setTimeout(() => c.kill('SIGKILL'), 3000);
    c.once('exit', () => { clearTimeout(t); resolve(); });
    c.kill('SIGTERM');
  });
}

async function restart() {
  if (status.phase === 'disabled' || status.phase === 'failed' || status.phase === 'downloading') return;
  await stop();
  restarts = 0;
  try { await prepareReality(); } catch (e) { status.reality.reason = e.message; }
  spawnXray();
}

function version() {
  return new Promise((resolve) => {
    const p = spawn(XRAY_BIN, ['version']);
    let out = '';
    p.stdout.on('data', (d) => (out += d));
    p.on('close', () => resolve(out.split('\n')[0].trim()));
    p.on('error', () => resolve('unknown'));
  });
}

/** Non-fatal boot: download if needed, then run. Resolves when done either way. */
async function boot() {
  if (!settings.enable.xray) return;
  if (!inbounds().length) { status.phase = 'disabled'; log('no Xray protocols enabled'); return; }
  try {
    await ensureBinary();
    status.version = await version();
    log(status.version);
    try { await prepareReality(); } catch (e) { status.reality.reason = e.message; log('reality not enabled:', e.message); }
    if (status.reality.active) log(`Reality on 127.0.0.1:${status.reality.loopPort} → public :${status.reality.port}${status.reality.extraPort ? ` and :${settings.port}` : ''} (sni ${realitySni()})`);
    else log(`Reality off: ${status.reality.reason}`);
    spawnXray();
  } catch (e) {
    status.phase = 'failed';
    status.error = e.message;
    log(`not available: ${e.message} — native protocols keep working`);
  }
}

module.exports = { boot, stop, restart, routes, inbounds, status, realitySni, XRAY_BIN };
