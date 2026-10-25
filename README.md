<div dir="rtl">

# V2Gate — سرور تک‌پورتی VLESS/Trojan با موتور بومی Node.js

یک اپ کوچک Node.js که روی **یک پورت** بالا می‌آید و **خودش** پروتکل‌های **VLESS** و **Trojan** را (روی WebSocket، HTTPUpgrade و **XHTTP**) اجرا می‌کند — بدون Xray، بدون باینری خارجی، بدون هیچ وابستگی npm. کانفیگ‌ها و لینک سابسکریپشن را از پنل می‌گیرید و با v2rayNG / Hiddify / v2rayN / Streisand / NekoBox / Clash استفاده می‌کنید.

- **کاملاً بومی**: WebSocket (RFC 6455)، XHTTP (SplitHTTP: بدون WebSocket، فقط GET/POST معمولی — برای شبکه‌هایی که اتصال‌های طولانی به CDN را می‌کُشند)، VLESS، Trojan، رله‌ی TCP و DNS همه در خود Node
- **IP تمیز**: لیست IPهای تمیز کلودفلر را در پنل بدهید یا با «اسکن خودکار» (سرور نامزدها را با SNI شما تأیید می‌کند، مرورگر شما از سمت ISP خودتان زمان‌گیری می‌کند) پیدا کنید؛ برای هر IP، کانفیگ جدا ساخته و به سابسکریپشن اضافه می‌شود
- **تست داخلی و تست از بیرون**: دو دکمه در پنل؛ اولی موتور و خروجی سرور را می‌سنجد، دومی از طریق آدرس عمومی (Cloudflare → Worker → هاست) به خود سرور تونل می‌زند تا کل زنجیره تأیید شود
- پنل فارسی با رمز، QR برای هر کانفیگ، سابسکریپشن base64 / خام / Clash
- مسیرهای WebSocket غیرقابل حدس، صفحه‌ی اصلی پوششی، قفل ورود بعد از ۵ تلاش ناموفق
- Dockerfile، Blueprint برای Render، docker-compose برای VPS، Worker برای کلودفلر

## چطور کار می‌کند؟

```text
 کلاینت (v2rayNG, Hiddify, …)
   │  TLS  →  به دامنه‌ی سرویس، یا به یک IP تمیز کلودفلر با SNI دامنه
   ▼
 Cloudflare (اختیاری: دامنه‌ی proxied یا Worker)
   ▼
 ┌─────────────────────────────────────────────┐
 │ V2Gate (Node, پورت $PORT)                   │
 │  /panel  /sub/<token>  /<مسیرهای WS>       │
 │  ws.js → proxy.js (VLESS | Trojan) → TCP   │ ──▶ اینترنت
 └─────────────────────────────────────────────┘
```

---

## ۱) دیپلوی از GitHub روی Render (رایگان)

1. این ریپو را Fork کنید یا کد را در ریپوی خودتان push کنید.
2. [render.com](https://render.com) → **New → Web Service** → ریپو را انتخاب کنید. Render فایل `Dockerfile` را تشخیص می‌دهد. Plan: **Free**.
3. **Environment** → این متغیرها را بدهید:

   | متغیر | مقدار |
   |---|---|
   | `PANEL_PASSWORD` | رمز پنل |
   | `UUID` | یک UUID ([uuidgenerator.net](https://www.uuidgenerator.net/)) |
   | `TROJAN_PASSWORD` | یک رمز تصادفی |
   | `SUB_TOKEN` | یک رشته‌ی تصادفی بدون فاصله |

   > دیسک رایگان Render پایدار نیست؛ بدون این‌ها با هر دیپلوی UUID عوض می‌شود. با **New → Blueprint** فایل `render.yaml` همه را خودکار می‌سازد و فقط `PANEL_PASSWORD` را می‌دهید.

4. **Create Web Service** → بعد از بیلد، `https://<app>.onrender.com/panel` را باز کنید.
5. اول دکمه‌ی **«تست داخلی پروکسی»** را بزنید. اگر «موفق» بود، سرور سالم است.
6. لینک سابسکریپشن را در کلاینت اضافه کنید و با **Real delay / URL test** تست بگیرید (نه TCP ping).

هر `git push` به `main` دیپلوی جدید می‌سازد. پلن رایگان بعد از ۱۵ دقیقه بی‌استفاده بودن خواب می‌رود و اولین اتصال بعدی ۳۰–۵۰ ثانیه طول می‌کشد.

## ۲) اگر کانفیگ وصل نشد ولی تست داخلی موفق بود → IP تمیز

یعنی مسیر شما تا سرور (دامنه/IP هاست) از سمت ISP بسته یا کند است. راه‌حل: سرویس را پشت **Cloudflare** ببرید و با IP تمیز وصل شوید.

**روش A — Cloudflare Worker (بدون دامنه‌ی شخصی):**

1. در [dash.cloudflare.com](https://dash.cloudflare.com) → **Workers & Pages → Create → Create Worker** → کد `cloudflare-worker.js` را جای‌گزین کنید و Deploy بزنید.
2. در تنظیمات Worker → **Variables** → `ORIGIN` = `your-app.onrender.com` (فقط هاست).
3. روی سرور V2Gate متغیر `HOST` را برابر دامنه‌ی Worker بگذارید (مثل `my-worker.me.workers.dev`) و ری‌دیپلوی کنید.
4. در پنل، بخش **IP تمیز**، چند IP تمیز کلودفلر (که در ISP شما جواب می‌دهد) وارد کنید و ذخیره بزنید.
5. سابسکریپشن را در کلاینت آپدیت کنید — برای هر IP تمیز، کانفیگ جدا دارید.

**روش B — دامنه‌ی شخصی روی Cloudflare:** یک رکورد CNAME (با ابر نارنجی/Proxied) به دامنه‌ی هاست بزنید، `HOST` را برابر دامنه‌ی خودتان بگذارید و همان مراحل ۴ و ۵.

> IP تمیز چیست؟ آدرس‌های لبه‌ی کلودفلر (مثل محدوده‌های `162.159.x.x` یا `188.114.x.x`) که در ISP شما بدون اختلال کار می‌کنند. کلاینت به آن IP وصل می‌شود ولی SNI و Host همان دامنه می‌ماند، پس کلودفلر درخواست را به سرویس شما می‌رساند. ابزارهای «CF IP scanner» برای پیدا کردن‌شان زیاد است.

## ۳) Railway / Koyeb / Fly.io

ریپو را وصل کنید، Dockerfile تشخیص داده می‌شود، همان متغیرها را ست کنید. دامنه و TLS خودکار تشخیص داده می‌شود (`TLS_MODE=proxy`، پورت عمومی `443`).

## ۴) VPS با Docker

```bash
git clone https://github.com/<شما>/<ریپو>.git && cd <ریپو>
cp .env.example .env     # اختیاری
docker compose up -d --build
```

`docker-compose.yml` پورت `443` را به اپ می‌دهد و `TLS_MODE=self` (گواهی خودامضا) فعال است. اگر پشت Cloudflare/nginx هستید، `TLS_MODE=proxy` بگذارید.

## ۵) هاست‌های Node.js (Pterodactyl و مشابه)

`package.json` و پوشه‌ی `src/` را آپلود کنید؛ Startup: `node src/index.js` — پورت از `SERVER_PORT` خوانده می‌شود. هیچ چیزی دانلود نمی‌شود و `npm install` لازم نیست.

## ۶) اجرای محلی

```bash
node src/index.js
# → http://localhost:3000/panel
```

---

## متغیرهای محیطی

همه اختیاری‌اند — `.env.example` را ببینید.

| متغیر | پیش‌فرض | توضیح |
|---|---|---|
| `PORT` / `SERVER_PORT` | `3000` | پورتی که اپ روی آن گوش می‌دهد |
| `HOST` | خودکار | دامنه در کانفیگ‌ها (SNI/Host) |
| `PUBLIC_PORT` | `443` روی PaaS، وگرنه `PORT` | پورتی که کلاینت‌ها به آن وصل می‌شوند |
| `TLS_MODE` | `proxy` روی PaaS، وگرنه `off` | `proxy` / `self` / `off` |
| `PANEL_PASSWORD` | — | رمز پنل (وگرنه بار اول پرسیده می‌شود) |
| `UUID` | تولید خودکار | شناسه‌ی VLESS |
| `TROJAN_PASSWORD` | تولید خودکار | رمز Trojan |
| `SUB_TOKEN` | تولید خودکار | توکن لینک سابسکریپشن |
| `CLEAN_IPS` | — | IPهای تمیز اولیه، با کاما |
| `PANEL_PATH` / `SUB_PATH` | `panel` / `sub` | مسیرها |
| `CONFIG_NAME` | `V2Gate` | نام کانفیگ‌ها |
| `ENABLE_VLESS_WS` `ENABLE_TROJAN_WS` `ENABLE_VLESS_HTTPUPGRADE` `ENABLE_TROJAN_HTTPUPGRADE` `ENABLE_VLESS_XHTTP` `ENABLE_TROJAN_XHTTP` | `true/true/true/false/true/false` | روشن/خاموش کردن هر ترکیب |
| `PATH_VLESS_WS` … | از روی UUID | مسیرهای WS |
| `DNS_RESOLVER` | `8.8.8.8` | رزولور برای DNS کلاینت (UDP→TCP) |
| `IDLE_TIMEOUT` | `300` | ثانیه؛ بستن اتصال بی‌کار |
| `BLOCK_PRIVATE` | `true` | بستن دسترسی به شبکه‌ی داخلی سرور |
| `VERBOSE` | `false` | لاگ هر اتصال |
| `DATA_DIR` | `data` | محل ذخیره‌ی state |

## مسیرها

| مسیر | توضیح |
|---|---|
| `/` | صفحه‌ی ساده (پوشش) |
| `/health` | وضعیت سرویس (JSON) |
| `/panel` | پنل مدیریت |
| `/sub/<token>` | سابسکریپشن base64 |
| `/sub/<token>?format=raw` | لینک‌ها به صورت متن |
| `/sub/<token>?format=clash` | فایل Clash Meta |

## محدودیت‌های موتور بومی

- **UDP**: فقط DNS (پورت ۵۳) پشتیبانی می‌شود (به TCP تبدیل و به `DNS_RESOLVER` فرستاده می‌شود). بازی‌ها و تماس‌های صوتی که UDP خالص می‌خواهند کار نمی‌کنند؛ مرور وب، یوتیوب، تلگرام و اینستاگرام مشکلی ندارند.
- **VMess و Shadowsocks** از طریق موتور اختیاری Xray ارائه می‌شوند (کنار موتور بومی). اگر دانلود Xray روی هاست ممکن نباشد، سرویس بدون آن‌ها بالا می‌آید؛ در Docker باینری در زمان بیلد داخل ایمیج می‌رود.
- **XHTTP** فقط در کلاینت‌های مبتنی بر Xray (v2rayNG، v2rayN، V2Box، Streisand) کار می‌کند و در خروجی Clash نمی‌آید.
- **XTLS/Reality** نیاز به کنترل مستقیم TLS دارند و روی هاست‌های تک‌پورتی PaaS قابل اجرا نیستند.

## نکات امنیتی

- لینک سابسکریپشن شامل توکن است؛ آن را عمومی نکنید.
- پوشه‌ی `data/` حاوی UUID، رمزها و کلید TLS است — در `.gitignore` هست.
- «ریست UUID و رمزها» همه‌ی کانفیگ‌ها و لینک سابسکریپشن را باطل می‌کند.

## عیب‌یابی

| علامت | معنی | کار |
|---|---|---|
| تست داخلی پنل **ناموفق** | سرور به اینترنت دسترسی ندارد یا هاست WebSocket را نمی‌بندد | لاگ سرویس را ببینید؛ هاست دیگری امتحان کنید |
| تست داخلی **موفق** ولی کلاینت وصل نمی‌شود | دامنه/IP هاست از ISP شما بسته است | IP تمیز + Cloudflare (بخش ۲) |
| کلاینت وصل می‌شود ولی بعد از چند دقیقه قطع می‌شود (Render) | سرویس رایگان خواب رفته | دوباره وصل شوید؛ یا هاستی بدون خواب |
| v2rayNG پینگ TCP نمی‌دهد | TCP ping به هاست‌های پشت CDN اغلب جواب نمی‌دهد | از **Real delay** استفاده کنید |
| کانفیگ‌ها بعد از هر دیپلوی عوض می‌شوند | دیسک پایدار نیست | `UUID`، `TROJAN_PASSWORD`، `SUB_TOKEN` را ست کنید |
| خطای گواهی در کلاینت | حالت `self` | «Allow insecure» را روشن کنید (در لینک‌ها هست) |

## ساختار پروژه

```text
src/index.js     سرور HTTP(S)، پنل، سابسکریپشن، تست داخلی، مسیردهی Upgrade
src/ws.js        WebSocket سرور/کلاینت (RFC 6455) و HTTPUpgrade — بدون وابستگی
src/proxy.js     موتور VLESS و Trojan: parse هدر، رله‌ی TCP، DNS برای UDP
src/xray.js      موتور اختیاری Xray: دانلود، کانفیگ، پروسه — VMess-WS/HU و Shadowsocks-WS روی 127.0.0.1
src/zip.js       استخراج آرشیو Xray بدون وابستگی
src/xhttp.js     ترنسپورت XHTTP (packet-up / stream-up / stream-one) به‌صورت Duplex
src/scan.js      یافتن IP تمیز: نمونه‌گیری از محدوده‌های Cloudflare و تأیید با SNI
src/config.js    متغیرهای محیطی و state ذخیره‌شده (UUID، رمزها، IPهای تمیز)
src/links.js     ساخت لینک‌های vless:// trojan:// (+ نسخه‌ی هر IP تمیز) و خروجی Clash
src/panel.js     HTML پنل
src/qr.js        تولید QR — بدون وابستگی
cloudflare-worker.js   Worker برای قرار دادن سرویس پشت کلودفلر
Dockerfile · render.yaml · docker-compose.yml · .github/workflows/docker.yml
```

## مجوز

MIT

</div>
