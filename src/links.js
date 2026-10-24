'use strict';
// Builds the share links (vless://, vmess://, trojan://) and subscription bodies.

const { settings, state, paths } = require('./config');

function tlsOn() {
  return settings.tlsMode === 'proxy' || settings.tlsMode === 'self';
}

function insecure() {
  // Self-signed cert → clients must skip verification.
  return settings.tlsMode === 'self';
}

function common() {
  const host = settings.host;
  const port = settings.publicPort;
  const tls = tlsOn();
  return { host, port, tls, insecure: insecure(), sni: host };
}

function name(label) {
  return `${settings.configName} ${label}`;
}

function q(params) {
  return Object.entries(params)
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
    .join('&');
}

function vlessLink({ path, network, label }) {
  const c = common();
  const params = {
    encryption: 'none',
    security: c.tls ? 'tls' : 'none',
    sni: c.tls ? c.sni : undefined,
    fp: c.tls ? 'chrome' : undefined,
    allowInsecure: c.tls && c.insecure ? '1' : undefined,
    type: network,
    host: c.host,
    path,
  };
  return `vless://${state.uuid}@${c.host}:${c.port}?${q(params)}#${encodeURIComponent(name(label))}`;
}

function vmessLink({ path, label }) {
  const c = common();
  const obj = {
    v: '2',
    ps: name(label),
    add: c.host,
    port: String(c.port),
    id: state.uuid,
    aid: '0',
    scy: 'auto',
    net: 'ws',
    type: 'none',
    host: c.host,
    path,
    tls: c.tls ? 'tls' : '',
    sni: c.tls ? c.sni : '',
    fp: c.tls ? 'chrome' : '',
    alpn: '',
  };
  if (c.tls && c.insecure) obj.allowInsecure = true;
  return 'vmess://' + Buffer.from(JSON.stringify(obj)).toString('base64');
}

function trojanLink({ path, label }) {
  const c = common();
  const params = {
    security: c.tls ? 'tls' : 'none',
    sni: c.tls ? c.sni : undefined,
    fp: c.tls ? 'chrome' : undefined,
    allowInsecure: c.tls && c.insecure ? '1' : undefined,
    type: 'ws',
    host: c.host,
    path,
  };
  return `trojan://${encodeURIComponent(state.trojanPassword)}@${c.host}:${c.port}?${q(params)}#${encodeURIComponent(name(label))}`;
}

// Returns [{ key, label, protocol, transport, link }]
function allConfigs() {
  const p = paths();
  const tls = tlsOn() ? 'TLS' : 'NoTLS';
  const out = [];
  if (settings.enable.vlessWs) {
    out.push({
      key: 'vlessWs',
      label: `VLESS WS ${tls}`,
      protocol: 'VLESS',
      transport: 'WebSocket',
      path: p.vlessWs,
      link: vlessLink({ path: p.vlessWs, network: 'ws', label: `VLESS-WS-${tls}` }),
    });
  }
  if (settings.enable.vmessWs) {
    out.push({
      key: 'vmessWs',
      label: `VMess WS ${tls}`,
      protocol: 'VMess',
      transport: 'WebSocket',
      path: p.vmessWs,
      link: vmessLink({ path: p.vmessWs, label: `VMess-WS-${tls}` }),
    });
  }
  if (settings.enable.trojanWs) {
    out.push({
      key: 'trojanWs',
      label: `Trojan WS ${tls}`,
      protocol: 'Trojan',
      transport: 'WebSocket',
      path: p.trojanWs,
      link: trojanLink({ path: p.trojanWs, label: `Trojan-WS-${tls}` }),
    });
  }
  if (settings.enable.vlessHttpUpgrade) {
    out.push({
      key: 'vlessHttpUpgrade',
      label: `VLESS HTTPUpgrade ${tls}`,
      protocol: 'VLESS',
      transport: 'HTTPUpgrade',
      path: p.vlessHttpUpgrade,
      link: vlessLink({ path: p.vlessHttpUpgrade, network: 'httpupgrade', label: `VLESS-HU-${tls}` }),
    });
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
  const c = common();
  const p = paths();
  const proxies = [];
  const push = (o) => proxies.push(o);
  const tlsBlock = c.tls
    ? `    tls: true\n    servername: ${c.sni}\n    skip-cert-verify: ${c.insecure}\n`
    : '';
  if (settings.enable.vlessWs) {
    push(
      `  - name: "${name('VLESS-WS')}"\n    type: vless\n    server: ${c.host}\n    port: ${c.port}\n    uuid: ${state.uuid}\n    udp: true\n    network: ws\n${tlsBlock}    ws-opts:\n      path: "${p.vlessWs}"\n      headers:\n        Host: ${c.host}\n`
    );
  }
  if (settings.enable.vmessWs) {
    push(
      `  - name: "${name('VMess-WS')}"\n    type: vmess\n    server: ${c.host}\n    port: ${c.port}\n    uuid: ${state.uuid}\n    alterId: 0\n    cipher: auto\n    udp: true\n    network: ws\n${tlsBlock}    ws-opts:\n      path: "${p.vmessWs}"\n      headers:\n        Host: ${c.host}\n`
    );
  }
  if (settings.enable.trojanWs) {
    push(
      `  - name: "${name('Trojan-WS')}"\n    type: trojan\n    server: ${c.host}\n    port: ${c.port}\n    password: "${state.trojanPassword}"\n    udp: true\n    network: ws\n    sni: ${c.sni}\n    skip-cert-verify: ${c.insecure}\n    ws-opts:\n      path: "${p.trojanWs}"\n      headers:\n        Host: ${c.host}\n`
    );
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

module.exports = { allConfigs, subscriptionRaw, subscriptionBase64, clashYaml, subscriptionUrl, tlsOn };
