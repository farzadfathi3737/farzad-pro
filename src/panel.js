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

// Shown right after a successful login; carries the Set-Cookie and then moves on.
function loginOkPage({ next, text = 'ورود موفق.' }) {
  return page(
    text,
    `<meta http-equiv="refresh" content="0;url=${esc(next)}">
<div class="card"><strong class="ok">${esc(text)}</strong> <span class="muted">در حال انتقال…</span>
<div class="row" style="margin-top:12px"><a class="btn ghost" href="${esc(next)}">اگر منتقل نشدید، اینجا بزنید</a></div></div>
<script>setTimeout(function(){location.replace(${JSON.stringify(next)})},150)</script>`
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
<div class="top"><strong>${esc(c.label)}</strong><span class="badge">${esc(c.protocol)} · ${esc(c.transport)}${c.engine === 'xray' ? ' · Xray' : ''}</span></div>
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

function xrayLine(x) {
  if (!x || x.phase === 'disabled') return '<span class="muted">غیرفعال</span>';
  if (x.phase === 'running') {
    const r = x.reality && x.reality.active
      ? ` · <span class="ok">Reality روی :${x.reality.port}</span>`
      : ` · <span class="muted">Reality خاموش${x.reality && x.reality.reason ? ' (' + esc(x.reality.reason) + ')' : ''}</span>`;
    return `<span class="ok">در حال اجرا</span> <span class="muted mono">${esc(x.version || '')} (pid ${x.pid})</span> <span class="muted">— VMess · Shadowsocks</span>${r}`;
  }
  if (x.phase === 'downloading') return '<span class="warn">در حال دانلود Xray از GitHub…</span> <span class="muted">(صفحه را بعداً تازه کنید)</span>';
  if (x.phase === 'starting') return '<span class="warn">در حال راه‌اندازی…</span>';
  if (x.phase === 'stopped') return '<span class="muted">متوقف</span>';
  return `<span style="color:var(--err)">در دسترس نیست</span> <span class="muted">${esc(x.error || '')} — کانفیگ‌های بومی (VLESS/Trojan/XHTTP) کار می‌کنند</span>`;
}

function dashboard({ panelPath, host, publicPort, tlsMode, publicOverride, reqAddr, mismatch, stats, xray, configs, cleanIps, subUrl, uptime, qrs, notice, sq = '', directAddr = '' }) {
  const act = (name) => `${esc(panelPath)}/${name}${esc(sq)}`;
  const tlsLabel = { proxy: 'TLS (توسط هاست / کلودفلر)', self: 'TLS (گواهی خودامضا)', off: 'بدون TLS' }[tlsMode] || tlsMode;
  const direct = configs.filter((c) => c.isDirect || c.transport === 'Reality');
  const main = configs.filter((c) => !c.isClean && !direct.includes(c));
  const clean = configs.filter((c) => c.isClean);
  const directBox = direct.length ? `
<h2 style="margin-top:22px">کانفیگ‌های مستقیم <span class="badge">بدون Cloudflare · ${esc(directAddr)}</span></h2>
<p class="muted" style="margin:0 0 10px">کلاینت مستقیم به IP و پورت سرور وصل می‌شود؛ دامنه، Worker و IP تمیز در مسیر نیستند. <b>Reality</b> نه گواهی می‌خواهد نه allowInsecure؛ «مستقیم» با گواهی خودامضا است (<span class="mono">allowInsecure=1</span> در لینک هست)؛ «مستقیم بدون TLS» برای وقتی است که جلوی پورت یک پروکسی HTTP نشسته و TLS را عبور نمی‌دهد (<span class="mono">curl -k https://IP:PORT/health</span> reset می‌دهد ولی <span class="mono">http://</span> جواب می‌دهد) — رمزنگاری لایه‌ی انتقال ندارد، ولی ترافیک داخل (HTTPS سایت‌ها) همچنان رمز است.</p>
<div class="grid">${direct.map((c) => configCard(c, qrs)).join('')}</div>` : '';

  const mismatchBox = mismatch
    ? `<div class="notice" style="border-color:var(--warn)">
<strong class="warn">⚠ آدرس کانفیگ‌ها با آدرسی که پنل را باز کرده‌اید فرق دارد.</strong>
<div class="muted" style="margin:6px 0 10px">شما از <span class="mono">${reqAddr.tls === 'proxy' ? 'https' : 'http'}://${esc(reqAddr.host)}:${reqAddr.port}</span> وارد شده‌اید، ولی کانفیگ‌ها به <span class="mono">${esc(host)}:${publicPort}</span> (${esc(tlsLabel)}) اشاره می‌کنند. اگر کلاینت‌ها باید از همین آدرسِ مرورگر وصل شوند، دکمه‌ی زیر را بزنید تا آدرس، پورت و TLS از روی همین درخواست تنظیم شود. <b>اگر آدرس نشان‌داده‌شده دامنه‌ی هاست است نه دامنه‌ی خودتان</b> (مثلاً پشت Worker هستید و Worker هدر Host را عوض می‌کند)، نزنید و به‌جایش <span class="mono">HOST</span> را روی دامنه‌ی خودتان بگذارید.</div>
<form method="post" action="${act('usehost')}"><button type="submit">استفاده از آدرس ${esc(reqAddr.host)}</button></form>
</div>`
    : '';

  return page(
    'پنل V2Gate',
    `<div class="top"><div><h1>V2Gate</h1><h2>پنل کانفیگ‌های VLESS / Trojan — موتور بومی Node.js</h2></div>
<form method="post" action="${act('logout')}"><button class="ghost" type="submit">خروج</button></form></div>

${notice ? `<div class="notice ${notice.ok ? 'ok' : 'err'}">${esc(notice.text)}</div>` : ''}
${sq ? `<div class="notice" style="border-color:var(--warn)"><strong class="warn">حالت بدون کوکی</strong> <span class="muted">— تشخیص مسیر کوکی:</span> <span id="ck" class="muted">در حال بررسی…</span>
<script>
(function(){try{document.cookie='v2g_probe=1; Path=${esc(panelPath)}; SameSite=Strict'+(location.protocol==='https:'?'; Secure':'')}catch(e){}
var stored=/v2g_probe=1/.test(document.cookie);
fetch('${act('echo')}',{credentials:'same-origin'}).then(function(r){return r.json()}).then(function(j){
 var el=document.getElementById('ck');
 var msg=[]; msg.push('مرورگر کوکی را ذخیره کرد: '+(stored?'بله':'خیر'));
 msg.push('کوکی به سرور رسید: '+(j.probeCookie?'بله':'خیر'));
 msg.push('کوکی ورود (HttpOnly) به سرور رسید: '+(j.sessionCookie?'بله':'خیر'));
 var verdict = !stored ? 'مرورگر کوکی را رد می‌کند (حالت خصوصی یا تنظیمات).' : !j.probeCookie ? 'مرورگر کوکی را می‌فرستد ولی Worker/پروکسی هاست هدر Cookie را حذف می‌کند.' : !j.sessionCookie ? 'کوکی‌های معمولی عبور می‌کنند ولی Set-Cookie ورود (HttpOnly/Secure) به مرورگر نرسیده — پروکسی Set-Cookie را حذف می‌کند.' : 'کوکی‌ها کار می‌کنند؛ دفعه‌ی بعد ورود عادی خواهد بود.';
 el.textContent = msg.join(' · ') + ' ⇒ ' + verdict;
}).catch(function(){document.getElementById('ck').textContent='بررسی انجام نشد.'});
})();
</script></div>` : ''}
${mismatchBox}

<div class="card"><div class="kv">
<b>آدرس سرور</b><span><span class="mono">${esc(host)}:${publicPort}</span>${publicOverride ? ` <span class="badge">تنظیم‌شده از پنل</span> <form method="post" action="${act('clearhost')}" style="display:inline"><button type="submit" class="ghost" style="padding:2px 8px;font-size:12px">پاک کردن</button></form>` : ''}</span>
<b>حالت TLS</b><span>${esc(tlsLabel)}</span>
<b>موتور بومی</b><span><span class="ok">فعال</span> <span class="muted">— VLESS · Trojan · XHTTP</span></span>
<b>موتور Xray</b><span>${xrayLine(xray)}</span>
<b>اتصال‌های فعال</b><span>${stats.active} <span class="muted">(کل: ${stats.total} · خطا: ${stats.errors})</span></span>
<b>ترافیک</b><span class="mono">↑ ${fmtBytes(stats.bytesIn)} &nbsp; ↓ ${fmtBytes(stats.bytesOut)}</span>
<b>مدت اجرا</b><span>${esc(uptime)}</span>
</div>
<div class="row" style="margin-top:12px">
<form method="post" action="${act('selftest')}"><button class="ghost" type="submit">۱ · تست داخلی</button></form>
<span class="muted">موتور پروکسی + خروجی سرور به اینترنت (بدون عبور از Cloudflare/هاست).</span>
</div>
<form method="post" action="${act('extest')}" class="row" style="margin-top:10px">
<button class="ghost" type="submit">۲ · تست از بیرون</button>
<input type="text" name="address" id="extest-address" placeholder="اختیاری: IP تمیز برای تست (خالی = دامنه)" style="flex:1;min-width:220px;max-width:360px;padding:8px 10px;font-size:13px">
<span class="muted">سرور از طریق آدرس عمومی (${esc(host)}:${publicPort}) به خودش وصل می‌شود — همان مسیری که کلاینت می‌رود، منهای ISP شما. اگر موفق شد، WebSocket از Cloudflare و هاست عبور می‌کند.</span>
</form></div>

<div class="card">
<div class="top"><strong>لینک سابسکریپشن</strong><span class="badge">v2rayNG · v2rayN · Hiddify · Streisand · NekoBox</span></div>
<p class="muted" style="margin:6px 0 10px">این لینک را در بخش Subscription برنامه‌تان اضافه کنید. همه کانفیگ‌ها (شامل IPهای تمیز) با یک‌بار آپدیت دریافت می‌شوند. این لینک را عمومی نکنید.</p>
<div class="row" style="align-items:flex-start"><img alt="QR" src="${qrs.__sub}" onclick="showQr(this.src,'لینک سابسکریپشن')" title="برای بزرگ‌نمایی کلیک کنید" style="width:140px;height:140px;border-radius:10px;background:#fff;padding:6px;cursor:zoom-in">
<div style="flex:1;min-width:240px"><div class="link mono" id="l-sub">${esc(subUrl)}</div>
<div class="row" style="margin-top:10px"><button type="button" class="ghost" onclick="copyText('l-sub',this)">کپی لینک</button>
<a class="btn ghost" href="${esc(subUrl)}?format=clash" download="v2gate.yaml">دانلود Clash</a>
<a class="btn ghost" href="${esc(subUrl)}?format=raw" target="_blank">متن خام</a></div></div></div>

<div style="border-top:1px solid var(--line);margin-top:14px;padding-top:12px">
<div class="top"><strong>سابسکریپشن سازگار</strong><span class="badge">V2Box · Streisand · Shadowrocket · کلاینت‌های قدیمی</span></div>
<p class="muted" style="margin:6px 0 8px">فقط VLESS و Trojan روی WebSocket — بدون XHTTP، HTTPUpgrade، VMess و Shadowsocks. بعضی کلاینت‌ها اگر حتی یک خطِ ناشناخته ببینند کل سابسکریپشن را رد می‌کنند؛ اگر لینک بالا در برنامه‌ای کار نکرد، این را بدهید.</p>
<div class="link mono" id="l-sub-compat">${esc(subUrl)}?exclude=compat</div>
<div class="row" style="margin-top:8px"><button type="button" class="ghost" onclick="copyText('l-sub-compat',this)">کپی لینک سازگار</button>
<span class="muted">فیلترهای دیگر: <span class="mono">?only=vless,ws</span> · <span class="mono">?exclude=clean</span> · <span class="mono">?only=xhttp</span></span></div>
</div>
</div>

${directBox}
<h2 style="margin-top:22px">کانفیگ‌های اصلی <span class="badge">از طریق ${esc(host)}</span></h2>
<div class="grid">${main.map((c) => configCard(c, qrs)).join('')}</div>

<div class="card">
<strong>IP تمیز (Clean IP)</strong>
<p class="muted" style="margin:6px 0 10px">
وقتی سرویس پشت <b>Cloudflare</b> است (دامنه‌ی proxied یا Worker)، می‌توانید به‌جای دامنه، به یکی از IPهای کلودفلر که در ISP شما سالم است وصل شوید؛ SNI و Host همچنان دامنه‌ی اصلی می‌ماند.
هر خط یک IP یا دامنه (مثل <span class="mono">162.159.x.x</span> یا یک ساب‌دامین CDN). برای هر IP، نسخه‌ای از همه‌ی کانفیگ‌ها ساخته و به سابسکریپشن اضافه می‌شود.
</p>
<form method="post" action="${act('cleanips')}" id="cleanips-form">
<textarea name="ips" id="cleanips-text" placeholder="162.159.192.1&#10;188.114.96.1&#10;cdn.example.com">${esc((cleanIps || []).join('\n'))}</textarea>
<div class="row" style="margin-top:10px"><button type="submit">ذخیره</button><span class="muted">${clean.length ? `${cleanIps.length} آدرس → ${clean.length} کانفیگ` : 'هنوز IP تمیزی ثبت نشده'}</span></div>
</form>

<div style="border-top:1px solid var(--line);margin:16px 0 0;padding-top:14px">
<div class="top"><strong>یافتن خودکار IP تمیز</strong><span class="badge">دو مرحله: سرور + مرورگر شما</span></div>
<p class="muted" style="margin:6px 0 10px">این اسکن را روی همان گوشی/اینترنتی اجرا کنید که می‌خواهید با آن وصل شوید. سرور چند ده IP کلودفلر را با SNI دامنه‌ی شما چک می‌کند که واقعاً این پنل را سرو کنند؛ بعد مرورگر شما همان‌ها را از سمت ISP خودتان زمان‌گیری می‌کند. نتیجه تقریبی است: IPهایی که سریع پاسخ می‌دهند را اضافه کنید و با Real delay در کلاینت تأیید بگیرید.</p>
<div class="row">
<button type="button" id="scan-btn" onclick="runScan()">اسکن خودکار</button>
<select id="scan-count" style="padding:9px 10px;border-radius:10px;border:1px solid var(--line);background:#0c0e12;color:var(--fg)">
<option value="40">۴۰ نامزد (سریع)</option><option value="80" selected>۸۰ نامزد</option><option value="150">۱۵۰ نامزد (کامل‌تر)</option></select>
<button type="button" class="ghost" onclick="runScan(document.getElementById('cleanips-text').value)">فقط لیست بالا را تست کن</button>
<span id="scan-status" class="muted"></span>
</div>
<div id="scan-results" style="margin-top:12px"></div>
</div>
<script>
var SCAN_URL = ${JSON.stringify(`${panelPath}/scan${sq}`)};
function fmtMs(n){return n>=1000?(n/1000).toFixed(1)+' s':Math.round(n)+' ms'}
function timeFromBrowser(ip){
  // The browser cannot set SNI for a bare IP, so the TLS handshake "fails" after it
  // completes; what we measure is how fast the edge answers from this network.
  return new Promise(function(res){
    var t0=performance.now(), done=false, ctrl=new AbortController();
    var timer=setTimeout(function(){if(done)return;done=true;ctrl.abort();res({ip:ip,ms:4000,state:'timeout'})},4000);
    fetch('https://'+ip+'/cdn-cgi/trace?'+Math.random(),{mode:'no-cors',cache:'no-store',signal:ctrl.signal,redirect:'manual'})
      .then(function(){if(done)return;done=true;clearTimeout(timer);res({ip:ip,ms:performance.now()-t0,state:'ok'})})
      .catch(function(){if(done)return;done=true;clearTimeout(timer);res({ip:ip,ms:performance.now()-t0,state:'reply'})});
  });
}
async function runScan(list){
  var btn=document.getElementById('scan-btn'), st=document.getElementById('scan-status'), out=document.getElementById('scan-results');
  btn.disabled=true; out.innerHTML='';
  try{
    var q = list && list.trim() ? '&ips='+encodeURIComponent(list) : '&count='+document.getElementById('scan-count').value;
    st.textContent='مرحله ۱: سرور دارد نامزدها را با SNI دامنه‌ی شما چک می‌کند…';
    var r = await fetch(SCAN_URL+(SCAN_URL.indexOf('?')>-1?'':'?')+q,{credentials:'same-origin'});
    var j = await r.json();
    if(j.error){st.textContent=j.error;return}
    if(!j.ok.length){st.textContent='هیچ‌کدام از '+j.tested+' نامزد این پنل را سرو نکرد. دوباره امتحان کنید.';return}
    st.textContent='مرحله ۲: مرورگر شما '+j.ok.length+' IP تأییدشده را از سمت ISP خودتان زمان‌گیری می‌کند…';
    var ips=j.ok.map(function(x){return x.ip}), timed=[], i=0, CONC=6;
    async function w(){while(i<ips.length){var ip=ips[i++];timed.push(await timeFromBrowser(ip));st.textContent='مرحله ۲: '+timed.length+'/'+ips.length+' …'}}
    await Promise.all(Array.from({length:Math.min(CONC,ips.length)},w));
    timed.sort(function(a,b){return a.ms-b.ms});
    var good=timed.filter(function(t){return t.state!=='timeout'});
    st.textContent='تمام شد: '+good.length+' از '+timed.length+' IP از این شبکه پاسخ دادند. سریع‌ترین‌ها بالا هستند.';
    var rows=timed.map(function(t){var slow=t.state==='timeout', cls=slow?'style="color:var(--err)"':(t.ms<800?'class="ok"':'style="color:var(--warn)"');
      return '<tr><td><input type="checkbox" value="'+t.ip+'" '+(!slow&&t.ms<800?'checked':'')+'></td><td class="mono">'+t.ip+'</td><td '+cls+'>'+(slow?'بی‌پاسخ (۴ ثانیه)':fmtMs(t.ms))+'</td></tr>'}).join('');
    out.innerHTML='<div style="overflow-x:auto"><table style="border-collapse:collapse;width:100%;font-size:13px"><tr><th></th><th style="text-align:right">IP</th><th style="text-align:right">زمان از مرورگر شما</th></tr>'+rows+'</table></div>'+
      '<div class="row" style="margin-top:10px"><button type="button" onclick="addSelected()">افزودن انتخاب‌شده‌ها به لیست و ذخیره</button><span class="muted">پیش‌فرض: پاسخ زیر ۰٫۸ ثانیه انتخاب شده</span></div>';
    out.querySelectorAll('table td,table th').forEach(function(c){c.style.padding='4px 8px';c.style.borderBottom='1px solid var(--line)'});
  }catch(e){st.textContent='اسکن ناموفق: '+e.message}finally{btn.disabled=false}
}
function addSelected(){
  var ta=document.getElementById('cleanips-text'); var have=ta.value.split(/\\s+/).filter(Boolean);
  document.querySelectorAll('#scan-results input[type=checkbox]:checked').forEach(function(c){if(have.indexOf(c.value)===-1)have.push(c.value)});
  ta.value=have.join('\\n'); document.getElementById('cleanips-form').submit();
}
</script>
${clean.length ? `<details><summary>نمایش کانفیگ‌های IP تمیز (${clean.length})</summary><div class="grid">${clean.map((c) => configCard(c, qrs)).join('')}</div></details>` : ''}
</div>

<div class="card">
<div class="top"><strong>آخرین درخواست‌ها به سرور</strong><div class="row"><button type="button" class="ghost" onclick="loadLog()">تازه‌سازی</button><label style="margin:0;display:flex;gap:6px;align-items:center"><input type="checkbox" id="log-auto" checked> خودکار هر ۵ ثانیه</label></div></div>
<p class="muted" style="margin:6px 0 10px">برای عیب‌یابی: در گوشی لینک سابسکریپشن را باز کن یا در کلاینت Real delay بزن، بعد این‌جا نگاه کن. اگر ردیفی نیامد، درخواست اصلاً به سرور نرسیده (ISP / Cloudflare / Worker). <span class="mono">upgrade 101</span> یعنی تونل برقرار شد؛ <span class="mono">404</span> روی <span class="mono">/sub/</span> یعنی توکن اشتباه است.</p>
<div style="overflow-x:auto"><table id="log-table" style="border-collapse:collapse;width:100%;font-size:12.5px"><thead><tr><th style="text-align:right;padding:4px 8px">زمان</th><th style="text-align:right;padding:4px 8px">نوع</th><th style="text-align:right;padding:4px 8px">مسیر</th><th style="text-align:right;padding:4px 8px">وضعیت</th><th style="text-align:right;padding:4px 8px">کلاینت</th><th style="text-align:right;padding:4px 8px">IP</th><th style="text-align:right;padding:4px 8px">Host</th></tr></thead><tbody><tr><td colspan="7" class="muted" style="padding:8px">در حال بارگذاری…</td></tr></tbody></table></div>
<script>
var LOG_URL = ${JSON.stringify(`${panelPath}/log${sq}`)};
function esc_(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
function loadLog(){
  fetch(LOG_URL,{credentials:'same-origin',cache:'no-store'}).then(function(r){return r.json()}).then(function(j){
    var tb=document.querySelector('#log-table tbody'); if(!j.entries.length){tb.innerHTML='<tr><td colspan="7" class="muted" style="padding:8px">هنوز درخواستی ثبت نشده.</td></tr>';return}
    tb.innerHTML=j.entries.map(function(e){
      var ago=Math.round((j.now-e.t)/1000); var when=ago<60?ago+' ثانیه پیش':ago<3600?Math.round(ago/60)+' دقیقه پیش':Math.round(ago/3600)+' ساعت پیش';
      var st=e.status; var col=st===101||st==='OK'||(st>=200&&st<300)?'var(--ok)':st==='RST'||st>=500?'var(--err)':st>=400?'var(--warn)':st==='…'?'var(--accent)':'inherit';
      var kind=e.kind==='upgrade'?'upgrade':e.kind==='tcp'?'tcp':e.method; var note=e.note?' <span class="muted">('+esc_(e.note)+')</span>':'';
      return '<tr><td style="padding:4px 8px;white-space:nowrap">'+when+'</td><td style="padding:4px 8px" class="mono">'+esc_(kind)+'</td><td style="padding:4px 8px" class="mono">'+esc_(e.path)+note+'</td><td style="padding:4px 8px;color:'+col+'" class="mono">'+(st==='…'?'در حال اجرا':esc_(st))+(e.ms!=null?' <span class="muted">'+e.ms+'ms</span>':' <span class="muted">'+Math.round((j.now-e.t)/1000)+'s</span>')+'</td><td style="padding:4px 8px">'+esc_(e.ua)+'</td><td style="padding:4px 8px" class="mono">'+esc_(e.ip)+'</td><td style="padding:4px 8px" class="mono">'+esc_(e.host)+'</td></tr>';
    }).join('');
    tb.querySelectorAll('td').forEach(function(c){c.style.borderBottom='1px solid var(--line)'});
  }).catch(function(){});
}
loadLog(); setInterval(function(){ if(document.getElementById('log-auto').checked) loadLog(); },5000);
</script>
</div>

<div class="card">
<strong>مدیریت</strong>
<p class="muted" style="margin:6px 0 10px">ریست کردن UUID همه کانفیگ‌ها و لینک سابسکریپشن فعلی را باطل می‌کند و باید دوباره در کلاینت‌ها وارد شوند.</p>
<div class="row">
${xray && xray.phase !== 'disabled' ? `<form method="post" action="${act('xray-restart')}"><button class="ghost" type="submit">ری‌استارت Xray</button></form>` : ''}
<form method="post" action="${act('rotate')}" onsubmit="return confirm('UUID و رمزها بازتولید شوند؟ کانفیگ‌های فعلی از کار می‌افتند.')"><button class="danger" type="submit">ریست UUID و رمزها</button></form>
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

module.exports = { setupPage, loginPage, loginOkPage, dashboard, decoyPage };
