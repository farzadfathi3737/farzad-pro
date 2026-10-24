FROM node:20-alpine
ENV NODE_ENV=production
WORKDIR /app

# openssl is only needed for TLS_MODE=self (self-signed certificate on a raw port)
RUN apk add --no-cache openssl

# No npm dependencies — the app is plain Node.js.
COPY package.json ./
COPY src ./src

# Persisted state (UUID, passwords, clean IPs, TLS cert). Mount a volume here to keep
# configs stable across redeploys; otherwise set UUID/TROJAN_PASSWORD/SUB_TOKEN/PANEL_PASSWORD.
VOLUME ["/app/data"]

ENV PORT=3000
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD wget -qO- "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1 || exit 1

CMD ["node", "src/index.js"]
