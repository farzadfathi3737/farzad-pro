# vless-ws-node — نقطهٔ خروج فرانسه

سرور VLESS روی WebSocket با Node خالص (بدون باینری Xray). پشت TLS هاست اجرا می‌شود؛
خودش روی HTTP ساده (`$PORT`) گوش می‌دهد.

## دیپلوی روی هاست Node (با گیت)

1. این پوشه را در یک ریپوی گیت بگذارید و push کنید.
2. در پنل هاست، متغیرهای محیطی:

| متغیر     | مقدار                                   |
|-----------|-----------------------------------------|
| `UUID`    | `bf7789c6-a217-4c23-9c4c-462bbfc9002f` (یا UUID خودتان) |
| `WS_PATH` | `/ws` (یا هر مسیر دلخواه)                |
| `PORT`    | معمولاً خود هاست ست می‌کند              |
| `LOG`     | `1` فقط برای عیب‌یابی                   |

3. Start command: `npm start`
4. تست: `https://DOMAIN/health` باید `ok` برگرداند.

چند کاربر: `UUID=uuid1,uuid2`

## سمت ایران (3x-ui)

`xray-outbound-france.json` را در **Xray Configs → Outbounds** اضافه کنید
(`YOUR-FRANCE-DOMAIN` را با دامنهٔ هاست فرانسه عوض کنید)، سپس در Routing:

- `geoip:ir` و `geosite:category-ir` → `direct`
- باقی → `france`

## تست محلی

```bash
npm install
node test.js
```

## محدودیت

فقط TCP (هاست‌های Node از UDP پشتیبانی نمی‌کنند). درخواست‌های UDP/MUX رد می‌شوند.
