// Cloudflare Worker that puts V2Gate behind Cloudflare so "clean IPs" can be used.
//
// Deploy: dash.cloudflare.com → Workers & Pages → Create → paste this file.
// Settings → Variables → add ORIGIN = your-app.onrender.com (host only, no https://).
//
// Then in the V2Gate panel set HOST to the worker's domain
// (e.g. my-worker.my-name.workers.dev) — or set the HOST env var on the server —
// and add clean Cloudflare IPs in the panel. Clients connect to the clean IP with
// SNI/Host = the worker domain; Cloudflare forwards the WebSocket to ORIGIN.
//
// Note: VLESS/Trojan over WebSocket pass through Workers unchanged; the proxy
// logic still runs on your Node server.

export default {
  async fetch(request, env) {
    const origin = env.ORIGIN;
    if (!origin) return new Response('ORIGIN variable is not set', { status: 500 });

    const url = new URL(request.url);
    url.hostname = origin;
    url.protocol = 'https:';
    url.port = '';

    const headers = new Headers(request.headers);
    headers.set('Host', origin);
    headers.set('X-Forwarded-Proto', 'https');
    // Tell the app which public domain the visitor actually used.
    headers.set('X-Forwarded-Host', new URL(request.url).host);

    // redirect: 'manual' — pass 3xx responses (and their Set-Cookie) to the browser untouched.
    const upstream = new Request(url.toString(), { method: request.method, headers, body: request.body, redirect: 'manual' });
    return fetch(upstream, { redirect: 'manual' });
  },
};
