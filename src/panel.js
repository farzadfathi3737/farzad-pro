'use strict';
// HTML templates for the panel (setup / login / dashboard) and the decoy home page.

const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const CSS = `
:root{--bg:#0f1115;--card:#171a21;--line:#262b36;--fg:#e8eaf0;--muted:#8b93a7;--acc:#4f8cff;--ok:#2ecc71;--err:#ff5c5c}
*{box-sizing:border-box}body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,"Vazirmatn",Tahoma,sans-serif;background:var(--bg);color:var(--fg);line-height:1.6}
.wrap{max-width:960px;margin:0 auto;padding:24px 16px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:0 0 12px;color:var(--muted);font-weight:500}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px;margin:14px 0}
label{display:block;font-size:13px;color:var(--muted);margin-bottom:6px}
input[type=password],input[type=text]{width:100%;padding:11px 12px;border-radius:10px;border:1px solid var(--line);background:#0c0e12;color:var(--fg);font-size:15px;direction:ltr}
button,.btn{cursor:pointer;border:0;border-radius:10px;padding:10px 16px;background:var(--acc);color:#fff;font-size:14px;font-weight:600}
button.ghost,.btn.ghost{background:transparent;border:1px solid var(--line);color:var(--fg)}
button.danger{background:#b23b3b}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.muted{color:var(--muted);font-size:13px}
.err{color:var(--err);font-size:13px;margin-top:8px}
.ok{color:var(--ok)}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;direction:ltr;unicode-bidi:plaintext}
.link{word-break:break-all;background:#0c0e12;border:1px solid var(--line);border-radius:10px;padding:10px;font-size:12px;max-height:110px;overflow:auto;direction:ltr;text-align:left}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px}
.cfg{display:flex;flex-direction:column;gap:10px}
.cfg img{width:160px;height:160px;border-radius:10px;background:#fff;padding:6px;align-self:center}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;border:1px solid var(--line);color:var(--muted)}
.kv{display:grid;grid-template-columns:140px 1fr;gap:6px 12px;font-size:14px}.kv b{color:var(--muted);font-weight:500}
.top{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}
a{color:var(--acc)}
@media (max-width:600px){.kv{grid-template-columns:1fr}}
`;

function page(title, body, extraHead = '') {
  return `<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow">
<title>${esc(title)}</title><style>${CSS}</style>${extraHead}</head><body><div class="wrap">${body}</div></body></html>`;
}

function setupPage({ action, error }) {
  return page(
    'راه‌اندازی پنل',
    `<h1>راه‌اندازی اولیه</h1><h2>برای پنل یک رمز عبور تعیین کنید. این رمز فقط یک‌بار قابل تنظیم است.</h2>
<form class="card" method="post" action="${esc(action)}">
<label>رمز عبور پنل (حداقل ۸ کاراکتر)</label><input type="password" name="password" minlength="8" required autofocus>
<label style="margin-top:12px">تکرار رمز</label><input type="password" name="confirm" minlength="8" required>
${error ? `<div class="err">${esc(error)}</div>` : ''}
<div class="row" style="margin-top:14px"><button type="submit">ذخیره و ورود</button></div></form>`
  );
}

function loginPage({ action, error }) {
  return page(
    'ورود به پنل',
    `<h1>ورود</h1><h2>رمز عبور پنل را وارد کنید.</h2>
<form class="card" method="post" action="${esc(action)}">
<label>رمز عبور</label><input type="password" name="password" required autofocus>
${error ? `<div class="err">${esc(error)}</div>` : ''}
<div class="row" style="margin-top:14px"><button type="submit">ورود</button></div></form>`
  );
}

function dashboard({ panelPath, host, publicPort, tlsMode, xray, xrayVersion, configs, subUrl, uptime, qrs }) {
  const tlsLabel = { proxy: 'TLS (توسط هاست)', self: 'TLS (گواهی خودامضا)', off: 'بدون TLS' }[tlsMode] || tlsMode;
  const xrayState = xray.running
    ? `<span class="ok">در حال اجرا</span> <span class="muted">(pid ${xray.pid})</span>`
    : `<span style="color:var(--err)">متوقف</span>`;

  const cards = configs
    .map(
      (c) => `<div class="card cfg">
<div class="top"><strong>${esc(c.label)}</strong><span class="badge">${esc(c.protocol)} · ${esc(c.transport)}</span></div>
<img alt="QR" src="${qrs[c.key]}">
<div class="link mono" id="l-${c.key}">${esc(c.link)}</div>
<div class="row"><button type="button" class="ghost" onclick="copyText('l-${c.key}',this)">کپی لینک</button></div>
</div>`
    )
    .join('');

  return page(
    'پنل V2Gate',
    `<div class="top"><div><h1>V2Gate</h1><h2>پنل کانفیگ‌های V2Ray / Xray</h2></div>
<form method="post" action="${esc(panelPath)}/logout"><button class="ghost" type="submit">خروج</button></form></div>

<div class="card"><div class="kv">
<b>آدرس سرور</b><span class="mono">${esc(host)}:${publicPort}</span>
<b>حالت TLS</b><span>${esc(tlsLabel)}</span>
<b>Xray</b><span>${xrayState} <span class="muted mono">${esc(xrayVersion)}</span></span>
<b>مدت اجرا</b><span>${esc(uptime)}</span>
</div></div>

<div class="card">
<div class="top"><strong>لینک سابسکریپشن</strong><span class="badge">v2rayNG · v2rayN · Hiddify · Streisand · NekoBox</span></div>
<p class="muted" style="margin:6px 0 10px">این لینک را در بخش Subscription برنامه‌تان اضافه کنید. همه کانفیگ‌ها با یک‌بار آپدیت دریافت می‌شوند. این لینک را عمومی نکنید.</p>
<div class="row" style="align-items:flex-start"><img alt="QR" src="${qrs.__sub}" style="width:140px;height:140px;border-radius:10px;background:#fff;padding:6px">
<div style="flex:1;min-width:240px"><div class="link mono" id="l-sub">${esc(subUrl)}</div>
<div class="row" style="margin-top:10px"><button type="button" class="ghost" onclick="copyText('l-sub',this)">کپی لینک</button>
<a class="btn ghost" href="${esc(subUrl)}?format=clash" download="v2gate.yaml">دانلود Clash</a>
<a class="btn ghost" href="${esc(subUrl)}?format=raw" target="_blank">متن خام</a></div></div></div>
</div>

<h2 style="margin-top:22px">کانفیگ‌ها</h2>
<div class="grid">${cards}</div>

<div class="card">
<strong>مدیریت</strong>
<p class="muted" style="margin:6px 0 10px">ریست کردن UUID همه کانفیگ‌ها و لینک سابسکریپشن فعلی را باطل می‌کند و باید دوباره در کلاینت‌ها وارد شوند.</p>
<div class="row">
<form method="post" action="${esc(panelPath)}/restart"><button class="ghost" type="submit">ری‌استارت Xray</button></form>
<form method="post" action="${esc(panelPath)}/rotate" onsubmit="return confirm('UUID و رمزها بازتولید شوند؟ کانفیگ‌های فعلی از کار می‌افتند.')"><button class="danger" type="submit">ریست UUID و رمزها</button></form>
</div></div>

<script>
function copyText(id,btn){var t=document.getElementById(id).textContent.trim();
var done=function(){var o=btn.textContent;btn.textContent='کپی شد ✓';setTimeout(function(){btn.textContent=o},1500)};
if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(t).then(done)}else{var ta=document.createElement('textarea');ta.value=t;document.body.appendChild(ta);ta.select();try{document.execCommand('copy');done()}catch(e){}document.body.removeChild(ta)}}
</script>`
  );
}

// Looks like an ordinary app placeholder to anyone probing the root URL.
function decoyPage() {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Service</title><style>body{font-family:system-ui,sans-serif;display:grid;place-items:center;height:100vh;margin:0;background:#fafafa;color:#333}
.b{text-align:center}h1{font-weight:500;font-size:22px}p{color:#777}</style></head>
<body><div class="b"><h1>It works!</h1><p>The service is running.</p></div></body></html>`;
}

module.exports = { setupPage, loginPage, dashboard, decoyPage };
