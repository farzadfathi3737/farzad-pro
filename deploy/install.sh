#!/usr/bin/env bash
# V2Gate VPS installer (Debian/Ubuntu, root). Installs Node 20 if missing, clones or
# updates the repo into /opt/v2gate, writes .env, opens firewall ports and starts a
# systemd service. Re-running it updates the code and keeps .env and data/.
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/<you>/<repo>/main/deploy/install.sh) https://github.com/<you>/<repo>.git
#   # or, from a clone:  sudo bash deploy/install.sh
set -euo pipefail

REPO_URL="${1:-}"
DIR=/opt/v2gate
APP_PORT="${APP_PORT:-2096}"        # Node app (panel + WS/XHTTP configs), self-signed TLS
REALITY_PORT="${REALITY_PORT:-443}" # VLESS + Reality (direct)

if [ "$(id -u)" -ne 0 ]; then echo "run as root (sudo)"; exit 1; fi

echo "== packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl git ca-certificates openssl unzip >/dev/null

if ! command -v node >/dev/null 2>&1 || [ "$(node -p 'process.versions.node.split(".")[0]')" -lt 18 ]; then
  echo "== installing Node.js 20"
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null
  apt-get install -y -qq nodejs >/dev/null
fi
echo "node $(node -v)"

echo "== code"
if [ -d "$DIR/.git" ]; then
  git -C "$DIR" pull --ff-only
elif [ -n "$REPO_URL" ]; then
  git clone --depth 1 "$REPO_URL" "$DIR"
elif [ -f "$(dirname "$0")/../package.json" ]; then
  mkdir -p "$DIR"; cp -r "$(dirname "$0")/.." "$DIR/"
else
  echo "usage: install.sh <git repo url>"; exit 1
fi

echo "== config"
if [ ! -f "$DIR/.env" ]; then
  read -rp "Panel password (min 8 chars): " PANEL_PASSWORD
  cat > "$DIR/.env" <<EOF
PORT=$APP_PORT
TLS_MODE=self
PANEL_PASSWORD=$PANEL_PASSWORD
ENABLE_REALITY=true
# extra public port for Reality (the main port serves it too)
REALITY_PORT=$REALITY_PORT
REALITY_DEST=dl.google.com:443
# HOST=your.domain.com      # optional: a domain pointing at this VPS (or proxied by Cloudflare)
EOF
  chmod 600 "$DIR/.env"
  echo "wrote $DIR/.env"
else
  echo "keeping existing $DIR/.env"
fi

echo "== service"
cat > /etc/systemd/system/v2gate.service <<EOF
[Unit]
Description=V2Gate proxy panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$DIR
ExecStart=$(command -v node) $DIR/src/index.js
Restart=always
RestartSec=3
Environment=NODE_ENV=production
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable v2gate >/dev/null
systemctl restart v2gate

echo "== firewall"
for p in "$APP_PORT" "$REALITY_PORT"; do
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q active; then ufw allow "$p"/tcp >/dev/null || true; fi
  # Oracle Cloud / some images ship with a REJECT rule in iptables before anything else.
  if command -v iptables >/dev/null 2>&1; then iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp --dport "$p" -j ACCEPT; fi
done
if command -v netfilter-persistent >/dev/null 2>&1; then netfilter-persistent save >/dev/null 2>&1 || true; fi

sleep 3
IP=$(curl -fsS --max-time 6 https://api64.ipify.org || hostname -I | awk '{print $1}')
echo
echo "================================================================"
echo " V2Gate is running."
echo "   panel : https://$IP:$APP_PORT/panel   (self-signed cert: accept the warning)"
echo "   reality port : $REALITY_PORT"
echo "   logs  : journalctl -u v2gate -f"
echo " On Oracle Cloud / AWS also open TCP $APP_PORT and $REALITY_PORT in the cloud console (Security List / Security Group)."
echo "================================================================"
