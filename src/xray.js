'use strict';
// Downloads the Xray-core binary (if missing), writes its config and keeps the
// process running. All inbounds listen on 127.0.0.1 and are reached only through
// the Node reverse proxy in index.js.

const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const { spawn } = require('child_process');
const zip = require('./zip');
const { settings, state, paths } = require('./config');

const BIN_DIR = settings.binDir;
const XRAY_BIN = path.join(BIN_DIR, process.platform === 'win32' ? 'xray.exe' : 'xray');
const CONFIG_FILE = path.join(settings.dataDir, 'xray.json');

function log(...a) {
  console.log('[xray]', ...a);
}

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
  if (platform === 'darwin') {
    return arch === 'arm64' ? 'Xray-macos-arm64-v8a.zip' : 'Xray-macos-64.zip';
  }
  if (platform === 'win32') {
    return arch === 'x64' ? 'Xray-windows-64.zip' : 'Xray-windows-32.zip';
  }
  throw new Error(`Unsupported platform ${platform}/${arch}`);
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
    if (redirects > 8) return reject(new Error('Too many redirects'));
    https
      .get(url, { headers: { 'User-Agent': 'v2gate' } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          return resolve(fetchBuffer(new URL(res.headers.location, url).toString(), redirects + 1));
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
        }
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve(Buffer.concat(chunks)));
        res.on('error', reject);
      })
      .on('error', reject);
  });
}

async function ensureBinary() {
  if (fs.existsSync(XRAY_BIN)) return XRAY_BIN;
  fs.mkdirSync(BIN_DIR, { recursive: true });
  const url = downloadUrl();
  log('downloading', url);
  const buf = await fetchBuffer(url);
  const entryName = process.platform === 'win32' ? 'xray.exe' : 'xray';
  const files = zip.extract(buf, [entryName, 'geoip.dat', 'geosite.dat']);
  const bin = files.get(entryName);
  if (!bin) throw new Error('xray binary not found in archive');
  fs.writeFileSync(XRAY_BIN, bin);
  for (const extra of ['geoip.dat', 'geosite.dat']) {
    if (files.has(extra)) fs.writeFileSync(path.join(BIN_DIR, extra), files.get(extra));
  }
  if (process.platform !== 'win32') fs.chmodSync(XRAY_BIN, 0o755);
  log('installed to', XRAY_BIN);
  return XRAY_BIN;
}

// ---- config ------------------------------------------------------------------
// Each protocol gets its own local port; index.js routes by URL path.
function inbounds() {
  const p = paths();
  const base = settings.xrayBasePort;
  const list = [];

  if (settings.enable.vlessWs) {
    list.push({
      key: 'vlessWs',
      tag: 'vless-ws',
      port: base,
      path: p.vlessWs,
      inbound: {
        tag: 'vless-ws',
        listen: '127.0.0.1',
        port: base,
        protocol: 'vless',
        settings: { clients: [{ id: state.uuid, level: 0 }], decryption: 'none' },
        streamSettings: { network: 'ws', security: 'none', wsSettings: { path: p.vlessWs } },
        sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'] },
      },
    });
  }
  if (settings.enable.vmessWs) {
    list.push({
      key: 'vmessWs',
      tag: 'vmess-ws',
      port: base + 1,
      path: p.vmessWs,
      inbound: {
        tag: 'vmess-ws',
        listen: '127.0.0.1',
        port: base + 1,
        protocol: 'vmess',
        settings: { clients: [{ id: state.uuid, level: 0 }] },
        streamSettings: { network: 'ws', security: 'none', wsSettings: { path: p.vmessWs } },
        sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'] },
      },
    });
  }
  if (settings.enable.trojanWs) {
    list.push({
      key: 'trojanWs',
      tag: 'trojan-ws',
      port: base + 2,
      path: p.trojanWs,
      inbound: {
        tag: 'trojan-ws',
        listen: '127.0.0.1',
        port: base + 2,
        protocol: 'trojan',
        settings: { clients: [{ password: state.trojanPassword, level: 0 }] },
        streamSettings: { network: 'ws', security: 'none', wsSettings: { path: p.trojanWs } },
        sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'] },
      },
    });
  }
  if (settings.enable.vlessHttpUpgrade) {
    list.push({
      key: 'vlessHttpUpgrade',
      tag: 'vless-hu',
      port: base + 3,
      path: p.vlessHttpUpgrade,
      inbound: {
        tag: 'vless-hu',
        listen: '127.0.0.1',
        port: base + 3,
        protocol: 'vless',
        settings: { clients: [{ id: state.uuid, level: 0 }], decryption: 'none' },
        streamSettings: {
          network: 'httpupgrade',
          security: 'none',
          httpupgradeSettings: { path: p.vlessHttpUpgrade },
        },
        sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'] },
      },
    });
  }
  return list;
}

function buildConfig() {
  const ib = inbounds();
  const rules = [];
  if (settings.blockPrivate) {
    rules.push({ type: 'field', ip: ['geoip:private'], outboundTag: 'block' });
  }
  return {
    log: { loglevel: settings.xrayLogLevel },
    inbounds: ib.map((x) => x.inbound),
    outbounds: [
      { tag: 'direct', protocol: 'freedom', settings: { domainStrategy: 'UseIP' } },
      { tag: 'block', protocol: 'blackhole' },
    ],
    routing: { domainStrategy: 'AsIs', rules },
  };
}

function writeConfig() {
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(buildConfig(), null, 2));
  return CONFIG_FILE;
}

// Map of URL path → local xray port, used by the reverse proxy.
function routes() {
  const map = new Map();
  for (const x of inbounds()) map.set(x.path, x.port);
  return map;
}

// ---- process -----------------------------------------------------------------
let child = null;
let stopping = false;
let restarts = 0;
let status = { running: false, pid: null, startedAt: null, lastExit: null };

function start() {
  writeConfig();
  stopping = false;
  const env = { ...process.env, XRAY_LOCATION_ASSET: BIN_DIR };
  child = spawn(XRAY_BIN, ['run', '-config', CONFIG_FILE], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  status = { running: true, pid: child.pid, startedAt: Date.now(), lastExit: null };
  log('started pid', child.pid);

  child.stdout.on('data', (d) => process.stdout.write('[xray] ' + d));
  child.stderr.on('data', (d) => process.stderr.write('[xray] ' + d));

  child.on('exit', (code, signal) => {
    status = { ...status, running: false, lastExit: { code, signal, at: Date.now() } };
    child = null;
    if (stopping) return;
    restarts += 1;
    const delay = Math.min(30000, 1000 * 2 ** Math.min(restarts, 5));
    log(`exited (code=${code} signal=${signal}); restarting in ${delay}ms`);
    setTimeout(start, delay);
  });
}

function stop() {
  return new Promise((resolve) => {
    stopping = true;
    if (!child) return resolve();
    const c = child;
    const t = setTimeout(() => c.kill('SIGKILL'), 3000);
    c.once('exit', () => {
      clearTimeout(t);
      resolve();
    });
    c.kill('SIGTERM');
  });
}

async function restart() {
  await stop();
  restarts = 0;
  start();
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

module.exports = { ensureBinary, start, stop, restart, routes, inbounds, status: () => status, version, XRAY_BIN };
