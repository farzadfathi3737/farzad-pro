'use strict';
// HTML templates for the panel (setup / login / dashboard) and the decoy home page.

const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const CSS = `
:root{--bg:#0f1115;--card:#171a21;--line:#262b36;--fg:#e8eaf0;--muted:#8b93a7;--acc:#4f8cff;--ok:#2ecc71;--err:#ff5c5c;--warn:#f5b84b}
*{box-sizing:border-box}body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,"Vazirmatn",Tahoma,sans-serif;background:var(--bg);color:var(--fg);line-height:1.6}
.wrap{max-width:960px;margin:0 auto;padding:24px 16px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:0 0 12px;color:var(--muted);font-weight:500}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px;margin:14px 0}
label{display:block;font-size:13px;color:var(--muted);margin-bottom:6px}
input[type=password],input[type=text],textarea{width:100%;padding:11px 12px;border-radius:10px;border:1px solid var(--line);background:#0c0e12;color:var(--fg);font-size:15px;direction:ltr;font-family:ui-monospace,Menlo,Consolas,monospace}
textarea{min-height:90px;resize:vertical}
button,.btn{cursor:pointer;border:0;border-radius:10px;padding:10px 16px;background:var(--acc);color:#fff;font-size:14px;font-weight:600;text-decoration:none;display:inline-block}
button.ghost,.btn.ghost{background:transparent;border:1px solid var(--line);color:var(--fg)}
button.danger{background:#b23b3b}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.muted{color:var(--muted);font-size:13px}
.err{color:var(--err);font-size:13px;margin-top:8px}
.ok{color:var(--ok)}.warn{color:var(--warn)}
.notice{border-radius:10px;padding:10px 14px;margin:12px 0;border:1px solid var(--line);background:#0c0e12}
.notice.ok{border-color:var(--ok)}.notice.err{border-color:var(--err);color:var(--fg)}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;direction:ltr;unicode-bidi:plaintext}
.link{word-break:break-all;background:#0c0e12;border:1px solid var(--line);border-radius:10px;padding:10px;font-size:12px;max-height:110px;overflow:auto;direction:ltr;text-align:left}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px}
.cfg{display:flex;flex-direction:column;gap:10px;margin:0}
.cfg img{width:200px;height:200px;border-radius:10px;background:#fff;padding:6px;align-self:center;cursor:zoom-in}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;border:1px solid var(--line);color:var(--muted)}
.kv{display:grid;grid-template-columns:150px 1fr;gap:6px 12px;font-size:14px}.kv b{color:var(--muted);font-weight:500}
.top{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}
a{color:var(--acc)}
details summary{cursor:pointer;color:var(--acc);font-size:14px;margin:8px 0}
@media (max-width:600px){.kv{grid-template-columns:1fr}}
`;

function page(title, body) {
  return `<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow">
<title>${esc(title)}</title><style>${CSS}</style></head><body><div class="wrap">${body}</div></body></html>`;
}

function setupPage({ action, error }) {
  return page(
    'راه‌اندازی پنل',
    `<h1>راه‌اندازی اولیه</h1><h2>برای پنل یک رمز عبور تعیین کنید.</h2>
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

function fmtBytes(n) {
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}

function configCard(c, qrs) {
  return `<div class="card cfg">
<div class="top"><strong>${esc(c.label)}</strong><span class="badge">${esc(c.protocol)} · ${esc(c.transport)}</span></div>
<img alt="QR" src="${qrs[c.key]}" onclick="showQr(this.src,'${esc(c.label)}')" title="برای بزرگ‌نمایی کلیک کنید">
<div class="link mono" id="l-${esc(c.key)}">${esc(c.link)}</div>
<div class="row"><button type="button" class="ghost" onclick="copyText('l-${esc(c.key)}',this)">کپی لینک</button>
<button type="button" class="ghost" onclick="showQr(document.getElementById('l-${esc(c.key)}').previousElementSibling.src,'${esc(c.label)}')">QR بزرگ</button></div>
</div>`;
}

const QR_MODAL = `
<div id="qrm" onclick="this.style.display='none'" style="display:none;position:fixed;inset:0;background:#000c;z-index:9;align-items:center;justify-content:center;flex-direction:column;gap:14px;cursor:zoom-out">
<img id="qrm-img" alt="QR" style="width:min(92vw,560px);height:min(92vw,560px);background:#fff;padding:14px;border-radius:14px">
<div id="qrm-cap" style="color:#fff;font-size:15px"></div>
<div class="muted">برای بستن کلیک کنید</div>
</div>
<script>
function showQr(src,cap){var m=document.getElementById('qrm');document.getElementById('qrm-img').src=src;document.getElementById('qrm-cap').textContent=cap||'';m.style.display='flex'}
</script>`;

function dashboard({ panelPath, host, publicPort, tlsMode, publicOverride, reqAddr, mismatch, stats, configs, cleanIps, subUrl, uptime, qrs, notice }) {
  const tlsLabel = { proxy: 'TLS (توسط هاست / کلودفلر)', self: 'TLS (گواهی خودامضا)', off: 'بدون TLS' }[tlsMode] || tlsMode;
  const main = configs.filter((c) => !c.isClean);
  const clean = configs.filter((c) => c.isClean);

  const mismatchBox = mismatch
    ? `<div class="notice" style="border-color:var(--warn)">
<strong class="warn">⚠ آدرس کانفیگ‌ها با آدرسی که پنل را باز کرده‌اید فرق دارد.</strong>
<div class="muted" style="margin:6px 0 10px">شما از <span class="mono">${reqAddr.tls === 'proxy' ? 'https' : 'http'}://${esc(reqAddr.host)}:${reqAddr.port}</span> وارد شده‌اید، ولی کانفیگ‌ها به <span class="mono">${esc(host)}:${publicPort}</span> (${esc(tlsLabel)}) اشاره می‌کنند. اگر کلاینت‌ها باید از همین آدرسِ مرورگر وصل شوند — که معمولاً همین‌طور است — دکمه‌ی زیر را بزنید تا آدرس، پورت و TLS از روی همین درخواست تنظیم شود.</div>
<form method="post" action="${esc(panelPath)}/usehost"><button type="submit">استفاده از آدرس ${esc(reqAddr.host)}</button></form>
</div>`
    : '';

  return page(
    'پنل V2Gate',
    `<div class="top"><div><h1>V2Gate</h1><h2>پنل کانفیگ‌های VLESS / Trojan — موتور بومی Node.js</h2></div>
<form method="post" action="${esc(panelPath)}/logout"><button class="ghost" type="submit">خروج</button></form></div>

${notice ? `<div class="notice ${notice.ok ? 'ok' : 'err'}">${esc(notice.text)}</div>` : ''}
${mismatchBox}

<div class="card"><div class="kv">
<b>آدرس سرور</b><span><span class="mono">${esc(host)}:${publicPort}</span>${publicOverride ? ` <span class="badge">تنظیم‌شده از پنل</span> <form method="post" action="${esc(panelPath)}/clearhost" style="display:inline"><button type="submit" class="ghost" style="padding:2px 8px;font-size:12px">پاک کردن</button></form>` : ''}</span>
<b>حالت TLS</b><span>${esc(tlsLabel)}</span>
<b>اتصال‌های فعال</b><span>${stats.active} <span class="muted">(کل: ${stats.total} · خطا: ${stats.errors})</span></span>
<b>ترافیک</b><span class="mono">↑ ${fmtBytes(stats.bytesIn)} &nbsp; ↓ ${fmtBytes(stats.bytesOut)}</span>
<b>مدت اجرا</b><span>${esc(uptime)}</span>
</div>
<div class="row" style="margin-top:12px">
<form method="post" action="${esc(panelPath)}/selftest"><button class="ghost" type="submit">تست داخلی پروکسی</button></form>
<span class="muted">یک اتصال VLESS از خود سرور به اینترنت برقرار می‌کند؛ اگر موفق بود یعنی موتور سالم است و مشکل احتمالی در مسیر شبکه‌ی شما تا سرور است.</span>
</div></div>

<div class="card">
<div class="top"><strong>لینک سابسکریپشن</strong><span class="badge">v2rayNG · v2rayN · Hiddify · Streisand · NekoBox</span></div>
<p class="muted" style="margin:6px 0 10px">این لینک را در بخش Subscription برنامه‌تان اضافه کنید. همه کانفیگ‌ها (شامل IPهای تمیز) با یک‌بار آپدیت دریافت می‌شوند. این لینک را عمومی نکنید.</p>
<div class="row" style="align-items:flex-start"><img alt="QR" src="${qrs.__sub}" onclick="showQr(this.src,'لینک سابسکریپشن')" title="برای بزرگ‌نمایی کلیک کنید" style="width:140px;height:140px;border-radius:10px;background:#fff;padding:6px;cursor:zoom-in">
<div style="flex:1;min-width:240px"><div class="link mono" id="l-sub">${esc(subUrl)}</div>
<div class="row" style="margin-top:10px"><button type="button" class="ghost" onclick="copyText('l-sub',this)">کپی لینک</button>
<a class="btn ghost" href="${esc(subUrl)}?format=clash" download="v2gate.yaml">دانلود Clash</a>
<a class="btn ghost" href="${esc(subUrl)}?format=raw" target="_blank">متن خام</a></div></div></div>
</div>

<h2 style="margin-top:22px">کانفیگ‌های اصلی</h2>
<div class="grid">${main.map((c) => configCard(c, qrs)).join('')}</div>

<div class="card">
<strong>IP تمیز (Clean IP)</strong>
<p class="muted" style="margin:6px 0 10px">
وقتی سرویس پشت <b>Cloudflare</b> است (دامنه‌ی proxied یا Worker)، می‌توانید به‌جای دامنه، به یکی از IPهای کلودفلر که در ISP شما سالم است وصل شوید؛ SNI و Host همچنان دامنه‌ی اصلی می‌ماند.
هر خط یک IP یا دامنه (مثل <span class="mono">162.159.x.x</span> یا یک ساب‌دامین CDN). برای هر IP، نسخه‌ای از همه‌ی کانفیگ‌ها ساخته و به سابسکریپشن اضافه می‌شود.
</p>
<form method="post" action="${esc(panelPath)}/cleanips">
<textarea name="ips" placeholder="162.159.192.1&#10;188.114.96.1&#10;cdn.example.com">${esc((cleanIps || []).join('\n'))}</textarea>
<div class="row" style="margin-top:10px"><button type="submit">ذخیره</button><span class="muted">${clean.length ? `${cleanIps.length} آدرس → ${clean.length} کانفیگ` : 'هنوز IP تمیزی ثبت نشده'}</span></div>
</form>
${clean.length ? `<details><summary>نمایش کانفیگ‌های IP تمیز (${clean.length})</summary><div class="grid">${clean.map((c) => configCard(c, qrs)).join('')}</div></details>` : ''}
</div>

<div class="card">
<strong>مدیریت</strong>
<p class="muted" style="margin:6px 0 10px">ریست کردن UUID همه کانفیگ‌ها و لینک سابسکریپشن فعلی را باطل می‌کند و باید دوباره در کلاینت‌ها وارد شوند.</p>
<div class="row">
<form method="post" action="${esc(panelPath)}/rotate" onsubmit="return confirm('UUID و رمزها بازتولید شوند؟ کانفیگ‌های فعلی از کار می‌افتند.')"><button class="danger" type="submit">ریست UUID و رمزها</button></form>
</div></div>

<script>
function copyText(id,btn){var t=document.getElementById(id).textContent.trim();
var done=function(){var o=btn.textContent;btn.textContent='کپی شد ✓';setTimeout(function(){btn.textContent=o},1500)};
if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(t).then(done)}else{var ta=document.createElement('textarea');ta.value=t;document.body.appendChild(ta);ta.select();try{document.execCommand('copy');done()}catch(e){}document.body.removeChild(ta)}}
</script>${QR_MODAL}`
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
