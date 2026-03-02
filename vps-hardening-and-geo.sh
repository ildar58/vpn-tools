#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "[!] Please run as root (e.g. sudo bash ... )"
  exit 1
fi

echo "[+] Applying UFW rules..."
ufw deny in 25/tcp
ufw deny in 587/tcp
ufw deny in 465/tcp
ufw deny out 25/tcp
ufw deny out 587/tcp
ufw deny out 465/tcp

ufw allow 443/tcp
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow from 84.200.193.142 to any port 2222
ufw allow from 109.122.199.37 to any port 9999
ufw allow from 81.200.151.202 to any port 9999
ufw allow from 95.85.240.116 to any port 9999

ufw default deny incoming
ufw --force enable
systemctl start ufw
systemctl enable ufw


echo "[+] Running system update..."
apt update && apt upgrade -yqq

SCRIPT_PATH="/usr/local/bin/update-xray-geo.sh"
XRAY_DIR="/opt/remnanode/xray/share"

echo "[+] Ensuring directories..."
mkdir -p "$XRAY_DIR"

echo "[+] Creating update script..."
cat << 'EOF' > "$SCRIPT_PATH"
#!/usr/bin/env bash
set -euo pipefail

DIR="/opt/remnanode/xray/share"
TMPDIR="$(mktemp -d)"
mkdir -p "$DIR"

GEOSITE_URL="https://github.com/hydraponique/roscomvpn-geosite/releases/latest/download/geosite.dat"
GEOIP_URL="https://github.com/hydraponique/roscomvpn-geoip/releases/latest/download/geoip.dat"

curl -fsSL "$GEOSITE_URL" -o "$TMPDIR/geosite.dat"
curl -fsSL "$GEOIP_URL" -o "$TMPDIR/geoip.dat"

mv "$TMPDIR/geosite.dat" "$DIR/geosite.dat"
mv "$TMPDIR/geoip.dat" "$DIR/geoip-custom.dat"
rm -rf "$TMPDIR"

docker restart remnanode
EOF

chmod +x "$SCRIPT_PATH"

echo "[+] Setting cron job..."
CRON_LINE="0 7 * * * /usr/local/bin/update-xray-geo.sh"
( crontab -l 2>/dev/null | grep -v '/usr/local/bin/update-xray-geo.sh' ; echo "$CRON_LINE" ) | crontab -

echo "[+] Running update immediately..."
/usr/local/bin/update-xray-geo.sh

echo "✅ Done"
echo "⏰ Scheduled daily at 07:00: /usr/local/bin/update-xray-geo.sh"
