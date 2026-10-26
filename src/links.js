'use strict';
// Builds the share links (vless://, trojan://) and subscription bodies, including
// one extra variant per "clean IP": the client connects to that address while the
// TLS SNI and Host header still carry the real hostname.

const { settings, state, paths } = require('./config');
const xray = require('./xray');

function tlsOn() {
  return settings.tlsMode === 'proxy' || settings.tlsMode === 'self';
}
function insecure() {
  return settings.tlsMode === 'self';
}
function directOn() {
  if (settings.direct === false) return false;
  return Boolean(settings.publicIp && settings.directTls);
}

function q(params) {
  return Object.entries(params)
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
    .join('&');
}

const name = (label) => `${settings.configName} ${label}`;

// Endpoint the link points at. Default: the public host behind the CDN/host proxy.
// `direct`: straight to the public IP:port with our self-signed certificate.
function endpoint(direct) {
  if (direct) {
    return { port: settings.directPort || settings.port, tls: true, sni: settings.directSni || settings.host, insecure: true, host: settings.directSni || settings.host };
  }
  return { port: settings.publicPort, tls: tlsOn(), sni: settings.host, insecure: insecure(), host: settings.host };
}

function vlessLink({ address, path, network, label, direct }) {
  const e = endpoint(direct);
  const params = {
    encryption: 'none',
    security: e.tls ? 'tls' : 'none',
    sni: e.tls ? e.sni : undefined,
    fp: e.tls ? 'chrome' : undefined,
    allowInsecure: e.tls && e.insecure ? '1' : undefined,
    type: network,
    host: e.host,
    path,
    // XHTTP behind a CDN must use packet-up (CDNs buffer streaming request bodies).
    mode: network === 'xhttp' ? (direct ? 'auto' : 'packet-up') : undefined,
  };
  return `vless://${state.uuid}@${address}:${e.port}?${q(params)}#${encodeURIComponent(name(label))}`;
}

function trojanLink({ address, path, network, label, direct }) {
  const e = endpoint(direct);
  const params = {
    security: e.tls ? 'tls' : 'none',
    sni: e.tls ? e.sni : undefined,
    fp: e.tls ? 'chrome' : undefined,
    allowInsecure: e.tls && e.insecure ? '1' : undefined,
    type: network,
    host: e.host,
    path,
    mode: network === 'xhttp' ? (direct ? 'auto' : 'packet-up') : undefined,
  };
  return `trojan://${encodeURIComponent(state.trojanPassword)}@${address}:${e.port}?${q(params)}#${encodeURIComponent(name(label))}`;
}

function vmessLink({ address, path, network, label, direct }) {
  const e = endpoint(direct);
  const obj = {
    v: '2', ps: name(label), add: address, port: String(e.port), id: state.uuid, aid: '0', scy: 'auto',
    net: network, type: 'none', host: e.host, path, tls: e.tls ? 'tls' : '', sni: e.tls ? e.sni : '',
    fp: e.tls ? 'chrome' : '', alpn: '',
  };
  if (e.tls && e.insecure) obj.allowInsecure = true;
  return 'vmess://' + Buffer.from(JSON.stringify(obj)).toString('base64');
}

// Shadowsocks over WebSocket (v2ray-plugin style): NekoBox, Shadowrocket, Clash Meta.
function ssLink({ address, path, label, direct }) {
  const e = endpoint(direct);
  const userinfo = Buffer.from(`${settings.ssMethod}:${state.ssPassword}`).toString('base64url');
  const plugin = ['v2ray-plugin', e.tls ? 'tls' : '', `host=${e.host}`, `path=${path}`, 'mode=websocket', e.tls && e.insecure ? 'skip-cert-verify' : '']
    .filter(Boolean).join(';');
  return `ss://${userinfo}@${address}:${e.port}?plugin=${encodeURIComponent(plugin)}#${encodeURIComponent(name(label))}`;
}

// VLESS + Reality: direct TCP to the VPS IP; SNI is the camouflage site, not ours.
function realityLink({ label }) {
  const address = settings.realityAddress || settings.publicIp || settings.host;
  const params = {
    encryption: 'none', flow: 'xtls-rprx-vision', security: 'reality',
    sni: xray.realitySni(), fp: 'chrome', pbk: state.realityPublicKey, sid: state.realityShortId, type: 'tcp',
  };
  return `vless://${state.uuid}@${address}:${xray.status.reality.port}?${q(params)}#${encodeURIComponent(name(label))}`;
}

// The protocol/transport combinations that are enabled.
function kinds() {
  const p = paths();
  const out = [];
  if (settings.enable.vlessWs) out.push({ key: 'vlessWs', protocol: 'VLESS', transport: 'WebSocket', network: 'ws', path: p.vlessWs, build: vlessLink, tag: 'VLESS-WS' });
  if (settings.enable.trojanWs) out.push({ key: 'trojanWs', protocol: 'Trojan', transport: 'WebSocket', network: 'ws', path: p.trojanWs, build: trojanLink, tag: 'Trojan-WS' });
  if (settings.enable.vlessHu) out.push({ key: 'vlessHu', protocol: 'VLESS', transport: 'HTTPUpgrade', network: 'httpupgrade', path: p.vlessHu, build: vlessLink, tag: 'VLESS-HU' });
  if (settings.enable.trojanHu) out.push({ key: 'trojanHu', protocol: 'Trojan', transport: 'HTTPUpgrade', network: 'httpupgrade', path: p.trojanHu, build: trojanLink, tag: 'Trojan-HU' });
  if (settings.enable.vlessXh) out.push({ key: 'vlessXh', protocol: 'VLESS', transport: 'XHTTP', network: 'xhttp', path: p.vlessXh, build: vlessLink, tag: 'VLESS-XHTTP' });
  if (settings.enable.trojanXh) out.push({ key: 'trojanXh', protocol: 'Trojan', transport: 'XHTTP', network: 'xhttp', path: p.trojanXh, build: trojanLink, tag: 'Trojan-XHTTP' });
  // Xray-served protocols appear only while Xray is actually running.
  if (xray.status.phase === 'running') {
    if (xray.status.reality.active && state.realityPublicKey) {
      out.push({ key: 'reality', protocol: 'VLESS', transport: 'Reality', network: 'tcp', path: null, build: realityLink, tag: 'Reality', engine: 'xray', direct: true });
    }
    if (settings.enable.vmessWs) out.push({ key: 'vmessWs', protocol: 'VMess', transport: 'WebSocket', network: 'ws', path: p.vmessWs, build: vmessLink, tag: 'VMess-WS', engine: 'xray' });
    if (settings.enable.vmessHu) out.push({ key: 'vmessHu', protocol: 'VMess', transport: 'HTTPUpgrade', network: 'httpupgrade', path: p.vmessHu, build: vmessLink, tag: 'VMess-HU', engine: 'xray' });
    if (settings.enable.ssWs) out.push({ key: 'ssWs', protocol: 'Shadowsocks', transport: 'WebSocket', network: 'ws', path: p.ssWs, build: ssLink, tag: 'SS-WS', engine: 'xray' });
  }
  return out;
}

/**
 * Returns [{ key, label, protocol, transport, path, address, isClean, link }]
 * Main entries first, then one entry per clean IP for every kind.
 */
function allConfigs() {
  const tls = tlsOn() ? 'TLS' : 'NoTLS';
  const out = [];
  for (const k of kinds()) {
    out.push({
      key: k.key, protocol: k.protocol, transport: k.transport, path: k.path, engine: k.engine || 'native',
      address: k.direct ? (settings.realityAddress || settings.publicIp || settings.host) : settings.host, isClean: false,
      label: k.direct ? `${k.protocol} ${k.transport}` : `${k.protocol} ${k.transport} ${tls}`,
      link: k.build({ address: settings.host, path: k.path, network: k.network, label: k.direct ? k.tag : `${k.tag}-${tls}` }),
    });
  }
  // Direct variants: public IP + raw port, self-signed TLS (no CDN in the path).
  if (directOn()) {
    for (const k of kinds()) {
      if (k.direct) continue; // Reality is already direct
      out.push({
        key: `${k.key}@direct`, protocol: k.protocol, transport: k.transport, path: k.path, engine: k.engine || 'native',
        address: settings.publicIp, isClean: false, isDirect: true,
        label: `${k.protocol} ${k.transport} · مستقیم`,
        link: k.build({ address: settings.publicIp, path: k.path, network: k.network, label: `${k.tag}-Direct`, direct: true }),
      });
    }
  }
  for (const ip of state.cleanIps || []) {
    for (const k of kinds()) {
      if (k.direct) continue; // Reality goes straight to the VPS; clean IPs don't apply
      out.push({
        key: `${k.key}@${ip}`, protocol: k.protocol, transport: k.transport, path: k.path, engine: k.engine || 'native',
        address: ip, isClean: true,
        label: `${k.protocol} ${k.transport} · ${ip}`,
        link: k.build({ address: ip, path: k.path, network: k.network, label: `${k.tag} ${ip}` }),
      });
    }
  }
  return out;
}

// Tags a config can be filtered by: protocol, transport, engine, clean/main.
function tagsOf(c) {
  return new Set([
    c.protocol.toLowerCase(),                                   // vless trojan vmess shadowsocks
    c.protocol === 'Shadowsocks' ? 'ss' : null,
    c.transport === 'WebSocket' ? 'ws' : c.transport.toLowerCase(), // ws httpupgrade xhttp reality
    c.engine,                                                   // native xray
    c.isClean ? 'clean' : c.isDirect ? 'direct' : 'main',
    c.transport === 'Reality' ? 'direct' : null,
  ].filter(Boolean));
}

/**
 * Build a predicate from ?only=a,b&exclude=c,d (comma lists of tags above).
 * "compat" is a shorthand for the set every client understands: vless/trojan over ws.
 */
function makeFilter({ only = '', exclude = '' } = {}) {
  const split = (s) => String(s || '').toLowerCase().split(/[\s,]+/).filter(Boolean);
  let onlyTags = split(only);
  let exTags = split(exclude);
  if (onlyTags.includes('compat') || exTags.includes('compat')) {
    onlyTags = onlyTags.filter((t) => t !== 'compat');
    exTags = [...exTags.filter((t) => t !== 'compat'), 'xhttp', 'httpupgrade', 'ss', 'vmess'];
  }
  return (c) => {
    const t = tagsOf(c);
    if (exTags.some((x) => t.has(x))) return false;
    if (onlyTags.length && !onlyTags.some((x) => t.has(x))) return false;
    return true;
  };
}

function subscriptionRaw(filter = () => true) {
  return allConfigs().filter(filter).map((c) => c.link).join('\n') + '\n';
}

function subscriptionBase64(filter) {
  return Buffer.from(subscriptionRaw(filter)).toString('base64');
}

// Minimal Clash Meta (mihomo) YAML — handy for Clash Verge / Stash / Hiddify.
function clashYaml(filter = () => true) {
  const tls = tlsOn();
  const proxies = [];
  for (const c of allConfigs().filter(filter)) {
    if (c.isDirect || c.transport === 'XHTTP' || c.transport === 'Reality' || c.protocol === 'VMess' || c.protocol === 'Shadowsocks') continue; // kept simple: vless/trojan over ws via the public host
    const n = name(c.isClean ? `${c.protocol}-${c.transport} ${c.address}` : `${c.protocol}-${c.transport}`);
    const common =
      `    server: ${c.address}\n    port: ${settings.publicPort}\n    udp: false\n` +
      `    network: ${c.transport === 'WebSocket' ? 'ws' : 'http-upgrade'}\n` +
      (tls ? `    tls: true\n    servername: ${settings.host}\n    skip-cert-verify: ${insecure()}\n` : '') +
      `    ws-opts:\n      path: "${c.path}"\n      headers:\n        Host: ${settings.host}\n`;
    if (c.protocol === 'VLESS') proxies.push(`  - name: "${n}"\n    type: vless\n    uuid: ${state.uuid}\n${common}`);
    else proxies.push(`  - name: "${n}"\n    type: trojan\n    password: "${state.trojanPassword}"\n${common.replace(/    tls: true\n    servername/, '    sni')}`);
  }
  const names = proxies.map((x) => x.match(/name: "(.+)"/)[1]);
  return (
    `mixed-port: 7890\nallow-lan: false\nmode: rule\nlog-level: info\n\nproxies:\n${proxies.join('')}\n` +
    `proxy-groups:\n  - name: "${settings.configName}"\n    type: url-test\n    url: https://www.gstatic.com/generate_204\n    interval: 300\n    proxies:\n${names.map((n) => `      - "${n}"`).join('\n')}\n\n` +
    `rules:\n  - GEOIP,private,DIRECT,no-resolve\n  - MATCH,${settings.configName}\n`
  );
}

function subscriptionUrl(baseUrl) {
  return `${baseUrl}${settings.subPath}/${state.subToken}`;
}

module.exports = { allConfigs, subscriptionRaw, subscriptionBase64, clashYaml, subscriptionUrl, makeFilter, tlsOn, insecure, directOn };
