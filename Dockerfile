# ---- stage 1: fetch Xray-core so the container never needs GitHub at runtime ----
FROM alpine:3.20 AS xray
ARG XRAY_VERSION=latest
ARG TARGETARCH
RUN apk add --no-cache curl unzip ca-certificates
RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) ASSET=Xray-linux-64.zip ;; \
      arm64) ASSET=Xray-linux-arm64-v8a.zip ;; \
      arm)   ASSET=Xray-linux-arm32-v7a.zip ;; \
      *)     ASSET=Xray-linux-64.zip ;; \
    esac; \
    if [ "$XRAY_VERSION" = "latest" ]; then \
      URL="https://github.com/XTLS/Xray-core/releases/latest/download/$ASSET"; \
    else \
      URL="https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION#v}/$ASSET"; \
    fi; \
    mkdir -p /out && curl -fsSL "$URL" -o /tmp/xray.zip && \
    unzip -o /tmp/xray.zip xray geoip.dat geosite.dat -d /out && chmod +x /out/xray

# ---- stage 2: the app ------------------------------------------------------------
FROM node:20-alpine
ENV NODE_ENV=production
WORKDIR /app

# openssl is only needed for TLS_MODE=self (self-signed certificate on a raw port)
RUN apk add --no-cache openssl

# No npm dependencies — the app is plain Node.js.
COPY package.json ./
COPY src ./src
COPY --from=xray /out ./bin

# Persisted state (UUID, passwords, TLS cert). Mount a volume here to keep configs
# stable across redeploys; otherwise set UUID/TROJAN_PASSWORD/SUB_TOKEN/PANEL_PASSWORD env vars.
VOLUME ["/app/data"]

ENV PORT=3000
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD wget -qO- "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1 || exit 1

CMD ["node", "src/index.js"]
