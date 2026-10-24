'use strict';
// Builds the share links (vless://, trojan://) and subscription bodies, including
// one extra variant per "clean IP": the client connects to that address while the
// TLS SNI and Host header still carry the real hostname.

const { settings, state, paths } = require('./config');

function tlsOn() {
  return settings.tlsMode === 'proxy' || settings.tlsMode === 'self';
}
function insecure() {
  return settings.tlsMode === 'self';
}

function q(params) {
  return Object.entries(params)
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
    .join('&');
}

const name = (label) => `${settings.configName} ${label}`;

function vlessLink({ address, path, network, label }) {
  const tls = tlsOn();
  const params = {
    encryption: 'none',
    security: tls ? 'tls' : 'none',
    sni: tls ? settings.host : undefined,
    fp: tls ? 'chrome' : undefined,
    allowInsecure: tls && insecure() ? '1' : undefined,
    type: network,
    host: settings.host,
    path,
  };
  return `vless://${state.uuid}@${address}:${settings.publicPort}?${q(params)}#${encodeURIComponent(name(label))}`;
}

function trojanLink({ address, path, network, label }) {
  const tls = tlsOn();
  const params = {
    security: tls ? 'tls' : 'none',
    sni: tls ? settings.host : undefined,
    fp: tls ? 'chrome' : undefined,
    allowInsecure: tls && insecure() ? '1' : undefined,
    type: network,
    host: settings.host,
    path,
  };
  return `trojan://${encodeURIComponent(state.trojanPassword)}@${address}:${settings.publicPort}?${q(params)}#${encodeURIComponent(name(label))}`;
}

// The protocol/transport combinations that are enabled.
function kinds() {
  const p = paths();
  const out = [];
  if (settings.enable.vlessWs) out.push({ key: 'vlessWs', protocol: 'VLESS', transport: 'WebSocket', network: 'ws', path: p.vlessWs, build: vlessLink, tag: 'VLESS-WS' });
  if (settings.enable.trojanWs) out.push({ key: 'trojanWs', protocol: 'Trojan', transport: 'WebSocket', network: 'ws', path: p.trojanWs, build: trojanLink, tag: 'Trojan-WS' });
  if (settings.enable.vlessHu) out.push({ key: 'vlessHu', protocol: 'VLESS', transport: 'HTTPUpgrade', network: 'httpupgrade', path: p.vlessHu, build: vlessLink, tag: 'VLESS-HU' });
  if (settings.enable.trojanHu) out.push({ key: 'trojanHu', protocol: 'Trojan', transport: 'HTTPUpgrade', network: 'httpupgrade', path: p.trojanHu, build: trojanLink, tag: 'Trojan-HU' });
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
      key: k.key, protocol: k.protocol, transport: k.transport, path: k.path,
      address: settings.host, isClean: false,
      label: `${k.protocol} ${k.transport} ${tls}`,
      link: k.build({ address: settings.host, path: k.path, network: k.network, label: `${k.tag}-${tls}` }),
    });
  }
  for (const ip of state.cleanIps || []) {
    for (const k of kinds()) {
      out.push({
        key: `${k.key}@${ip}`, protocol: k.protocol, transport: k.transport, path: k.path,
        address: ip, isClean: true,
        label: `${k.protocol} ${k.transport} · ${ip}`,
        link: k.build({ address: ip, path: k.path, network: k.network, label: `${k.tag} ${ip}` }),
      });
    }
  }
  return out;
}

function subscriptionRaw() {
  return allConfigs().map((c) => c.link).join('\n') + '\n';
}

function subscriptionBase64() {
  return Buffer.from(subscriptionRaw()).toString('base64');
}

// Minimal Clash Meta (mihomo) YAML — handy for Clash Verge / Stash / Hiddify.
function clashYaml() {
  const tls = tlsOn();
  const proxies = [];
  for (const c of allConfigs()) {
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

module.exports = { allConfigs, subscriptionRaw, subscriptionBase64, clashYaml, subscriptionUrl, tlsOn, insecure };
