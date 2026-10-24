<div dir="rtl">

# V2Gate — پنل تک‌پورتی V2Ray/Xray برای هاست‌های Node.js

یک اپ کوچک Node.js که روی **یک پورت** بالا می‌آید، هسته‌ی [Xray-core](https://github.com/XTLS/Xray-core) را خودش دانلود و اجرا می‌کند، و کانفیگ‌های **VLESS / VMess / Trojan** (WebSocket و HTTPUpgrade) به‌علاوه‌ی یک **لینک سابسکریپشن** تحویل می‌دهد. مناسب هاست‌هایی مثل Render، Railway، Koyeb، هاست‌های رایگان Node.js (Pterodactyl) و همین‌طور VPS با Docker.

- **بدون هیچ وابستگی npm** — فقط `node src/index.js`
- پنل مدیریت با رمز عبور، QR برای هر کانفیگ، لینک سابسکریپشن (base64 / خام / Clash)
- مسیرهای WebSocket غیرقابل حدس (از روی UUID ساخته می‌شوند)
- صفحه‌ی اصلی یک صفحه‌ی ساده و بی‌خطر نشان می‌دهد؛ پنل روی مسیر جداست
- تشخیص خودکار هاست‌های PaaS (دامنه و TLS)
- ری‌استارت خودکار Xray در صورت کرش

## چطور کار می‌کند؟

```text
 کلاینت (v2rayNG, Hiddify, …)
        │  TLS (توسط هاست)  یا  مستقیم
        ▼
 ┌──────────────────────────┐    127.0.0.1:1010x    ┌───────────┐
 │  V2Gate  (Node, پورت $PORT)│ ───────────────────▶ │ Xray-core │ ──▶ اینترنت
 │  /panel  /sub/<token>    │   هر پروتکل یک پورت   └───────────┘
 └──────────────────────────┘
```

Node فقط نقش reverse-proxy برای درخواست‌های Upgrade دارد و کار اصلی پروکسی را Xray انجام می‌دهد.

---

## ۱) دیپلوی از GitHub روی Render (پیشنهادی — رایگان)

1. این ریپو را Fork کنید (یا کد را در یک ریپوی جدید خودتان push کنید).
2. در [render.com](https://render.com) → **New → Web Service** → ریپو را انتخاب کنید.
3. Render فایل `Dockerfile` را خودش تشخیص می‌دهد. Plan را **Free** بگذارید.
4. در بخش **Environment** این متغیرها را اضافه کنید (مقدارها دلخواه):

   | متغیر | مقدار |
   |---|---|
   | `PANEL_PASSWORD` | رمز پنل |
   | `UUID` | یک UUID (از [uuidgenerator.net](https://www.uuidgenerator.net/)) |
   | `TROJAN_PASSWORD` | یک رمز تصادفی |
   | `SUB_TOKEN` | یک رشته‌ی تصادفی (بدون فاصله) |

   > چون دیسک رایگان Render پایدار نیست، این مقادیر را حتماً ست کنید تا با هر دیپلوی عوض نشوند.
   > اگر از **Blueprint** استفاده کنید (New → Blueprint)، فایل `render.yaml` همه را خودکار می‌سازد و فقط `PANEL_PASSWORD` را خودتان می‌دهید.

5. **Create Web Service** → چند دقیقه صبر کنید تا بیلد تمام شود.
6. به `https://<نام-اپ>.onrender.com/panel` بروید، وارد شوید و لینک سابسکریپشن را کپی کنید.

هر `git push` به شاخه‌ی `main`، دیپلوی جدید می‌سازد.

> نکته: پلن رایگان Render بعد از ۱۵ دقیقه بی‌استفاده بودن، سرویس را خواب می‌کند و اولین اتصال بعدی ۳۰–۵۰ ثانیه طول می‌کشد.

## ۲) Railway / Koyeb / Fly.io

همین روند: ریپو را وصل کنید، Dockerfile تشخیص داده می‌شود، همان متغیرهای بالا را ست کنید. دامنه و TLS خودکار تشخیص داده می‌شود (`TLS_MODE=proxy`، پورت عمومی `443`).

## ۳) VPS با Docker

```bash
git clone https://github.com/<شما>/<ریپو>.git && cd <ریپو>
cp .env.example .env     # اختیاری — ویرایش کنید
docker compose up -d --build
```

`docker-compose.yml` پورت `443` را به اپ می‌دهد و `TLS_MODE=self` (گواهی خودامضا) فعال است. اگر پشت Cloudflare یا nginx هستید، `TLS_MODE=proxy` بگذارید.

یا بدون بیلد، از ایمیجی که GitHub Actions می‌سازد:

```bash
docker run -d --name v2gate --restart unless-stopped \
  -p 443:3000 -e PUBLIC_PORT=443 -e TLS_MODE=self -e PANEL_PASSWORD=secret \
  -v $PWD/data:/app/data ghcr.io/<شما>/<ریپو>:latest
```

## ۴) هاست‌های Node.js (Pterodactyl و مشابه)

1. فایل‌های `package.json` و پوشه‌ی `src/` را آپلود کنید (یا از Git clone هاست استفاده کنید).
2. Startup command: `node src/index.js` — پورت از `SERVER_PORT` خوانده می‌شود.
3. بار اول Xray از GitHub دانلود می‌شود (چند ثانیه). اگر هاست TLS ندارد، کانفیگ‌ها بدون TLS ساخته می‌شوند؛ برای TLS خودامضا `TLS_MODE=self` بگذارید (به `openssl` نیاز دارد).

## ۵) اجرای محلی

```bash
node src/index.js
# → http://localhost:3000/panel
```

---

## متغیرهای محیطی

همه اختیاری‌اند. فایل `.env.example` را ببینید.

| متغیر | پیش‌فرض | توضیح |
|---|---|---|
| `PORT` / `SERVER_PORT` | `3000` | پورتی که اپ روی آن گوش می‌دهد |
| `HOST` | خودکار | دامنه/IP عمومی در کانفیگ‌ها |
| `PUBLIC_PORT` | `443` روی PaaS، وگرنه `PORT` | پورتی که کلاینت‌ها به آن وصل می‌شوند |
| `TLS_MODE` | `proxy` روی PaaS، وگرنه `off` | `proxy` / `self` / `off` |
| `PANEL_PASSWORD` | — | رمز پنل (در غیر این صورت بار اول از شما پرسیده می‌شود) |
| `UUID` | تولید خودکار | شناسه‌ی VLESS/VMess |
| `TROJAN_PASSWORD` | تولید خودکار | رمز Trojan |
| `SUB_TOKEN` | تولید خودکار | توکن لینک سابسکریپشن |
| `PANEL_PATH` | `panel` | مسیر پنل |
| `SUB_PATH` | `sub` | مسیر سابسکریپشن |
| `CONFIG_NAME` | `V2Gate` | نام کانفیگ‌ها در کلاینت |
| `ENABLE_VLESS_WS` `ENABLE_VMESS_WS` `ENABLE_TROJAN_WS` `ENABLE_VLESS_HTTPUPGRADE` | `true` | روشن/خاموش کردن هر پروتکل |
| `PATH_VLESS_WS` … | از روی UUID | مسیرهای WebSocket |
| `XRAY_VERSION` | `latest` | نسخه‌ی Xray |
| `BLOCK_PRIVATE` | `true` | بستن دسترسی به شبکه‌ی داخلی سرور |
| `DATA_DIR` | `data` | محل ذخیره‌ی state (UUID، رمزها، گواهی) |

## مسیرها

| مسیر | توضیح |
|---|---|
| `/` | صفحه‌ی ساده (پوشش) |
| `/health` | وضعیت سرویس (JSON) — برای health check هاست |
| `/panel` | پنل مدیریت |
| `/sub/<token>` | سابسکریپشن base64 |
| `/sub/<token>?format=raw` | لینک‌ها به صورت متن |
| `/sub/<token>?format=clash` | فایل Clash Meta |

## استفاده در کلاینت

لینک سابسکریپشن را در **v2rayNG / v2rayN / Hiddify / Streisand / NekoBox / Clash Verge** به‌عنوان Subscription اضافه کنید و Update بزنید. برای تست اتصال از **Real delay / URL test** استفاده کنید نه TCP ping.

## نکات امنیتی

- لینک سابسکریپشن شامل توکن است؛ آن را عمومی نکنید.
- پوشه‌ی `data/` حاوی UUID، رمزها و کلید TLS است — در `.gitignore` هست و نباید commit شود.
- دکمه‌ی «ریست UUID و رمزها» در پنل همه‌ی کانفیگ‌ها و لینک سابسکریپشن را باطل می‌کند.
- ورود به پنل بعد از ۵ تلاش ناموفق، ۱۰ دقیقه برای آن IP قفل می‌شود.

## عیب‌یابی

- **Xray بالا نمی‌آید / کانفیگ وصل نمی‌شود:** لاگ سرویس را ببینید. اگر دانلود Xray از GitHub شکست خورده، سرویس را ری‌استارت کنید یا از Dockerfile استفاده کنید (Xray در زمان بیلد دانلود می‌شود).
- **روی PaaS بعد از هر دیپلوی کانفیگ‌ها عوض می‌شوند:** `UUID`، `TROJAN_PASSWORD`، `SUB_TOKEN` و `PANEL_PASSWORD` را به‌عنوان متغیر محیطی ست کنید.
- **کلاینت خطای گواهی می‌دهد:** در حالت `self` لینک‌ها `allowInsecure=1` دارند؛ در کلاینت «Allow insecure» را روشن کنید.
- **صفحه‌ی `/panel` ۴۰۴ می‌دهد:** `PANEL_PATH` را عوض کرده‌اید؛ همان مسیر را باز کنید.

## ساختار پروژه

```text
src/index.js   سرور HTTP(S)، پنل، سابسکریپشن، reverse-proxy برای WebSocket
src/xray.js    دانلود، تنظیم و مدیریت پروسه‌ی Xray
src/config.js  متغیرهای محیطی و state ذخیره‌شده
src/links.js   ساخت لینک‌های vless:// vmess:// trojan:// و خروجی Clash
src/panel.js   HTML پنل
src/qr.js      تولید QR (بدون وابستگی)
src/zip.js     استخراج آرشیو Xray (بدون وابستگی)
Dockerfile     ایمیج آماده با Xray داخلش
render.yaml    Blueprint برای Render
docker-compose.yml   اجرا روی VPS
.github/workflows/docker.yml   بیلد و انتشار ایمیج در GHCR
```

## مجوز

MIT

</div>
