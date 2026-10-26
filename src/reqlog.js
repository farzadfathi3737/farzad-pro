'use strict';
// In-memory ring buffer of recent requests for the panel's diagnostics view.
// Tokens and session ids in paths are masked before storing.

const MAX = 300;
const entries = [];

function maskPath(p) {
  return String(p)
    .replace(/(\/sub\/)[A-Za-z0-9_-]{6,}/, '$1***')
    .replace(/([?&]s=)[^&]+/, '$1***')
    .replace(/(\/x?h[a-z]*-[0-9a-f]{8}\/)[A-Za-z0-9_-]+/, '$1<session>');
}

function add(e) {
  const entry = { t: Date.now(), ...e, path: maskPath(e.path || '') };
  entries.push(entry);
  if (entries.length > MAX) entries.splice(0, entries.length - MAX);
  return entry; // callers may update status/ms later (in-flight requests)
}

function recent(n = 100) {
  return entries.slice(-n).reverse();
}

function shortUa(ua) {
  if (!ua) return '-';
  const s = String(ua);
  if (/v2box/i.test(s)) return 'V2Box';
  if (/v2rayng/i.test(s)) return 'v2rayNG';
  if (/v2rayn/i.test(s)) return 'v2rayN';
  if (/hiddify/i.test(s)) return 'Hiddify';
  if (/streisand/i.test(s)) return 'Streisand';
  if (/nekobox|sing-box|singbox/i.test(s)) return 'sing-box';
  if (/clash|mihomo|stash/i.test(s)) return 'Clash';
  if (/shadowrocket/i.test(s)) return 'Shadowrocket';
  if (/go-http-client/i.test(s)) return 'Go client';
  if (/iphone|ipad/i.test(s)) return 'Safari iOS';
  if (/android/i.test(s)) return 'Android browser';
  if (/windows/i.test(s)) return 'Windows browser';
  if (/macintosh/i.test(s)) return 'Mac browser';
  if (/curl/i.test(s)) return 'curl';
  return s.slice(0, 24);
}

module.exports = { add, recent, shortUa };
