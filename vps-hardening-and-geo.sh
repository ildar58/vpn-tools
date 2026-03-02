#!/usr/bin/env bash
set -euo pipefail

log_ok() { echo "[+] $*"; }
log_info() { echo "[=] $*"; }
log_warn() { echo "[!] $*"; }

if [[ "${EUID}" -ne 0 ]]; then
  log_warn "Please run as root (e.g. sudo bash ... )"
  exit 1
fi

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log_warn "Required command not found: $cmd"
    exit 1
  fi
}

ensure_ufw_rule() {
  local rule="$1"
  if ufw status | grep -Fq "$rule"; then
    log_info "UFW rule already exists: $rule"
  else
    log_ok "Adding UFW rule: $rule"
    # shellcheck disable=SC2086
    ufw $rule
  fi
}

require_cmd ufw
require_cmd curl
require_cmd crontab
require_cmd docker
require_cmd apt
require_cmd systemctl

log_ok "Applying UFW rules..."
ensure_ufw_rule "deny in 25/tcp"
ensure_ufw_rule "deny in 587/tcp"
ensure_ufw_rule "deny in 465/tcp"
ensure_ufw_rule "deny out 25/tcp"
ensure_ufw_rule "deny out 587/tcp"
ensure_ufw_rule "deny out 465/tcp"

ensure_ufw_rule "allow 443/tcp"
ensure_ufw_rule "allow 22/tcp"
ensure_ufw_rule "allow 80/tcp"
ensure_ufw_rule "allow from 84.200.193.142 to any port 2222"
ensure_ufw_rule "allow from 109.122.199.37 to any port 9999"
ensure_ufw_rule "allow from 81.200.151.202 to any port 9999"
ensure_ufw_rule "allow from 95.85.240.116 to any port 9999"

log_ok "Setting UFW default policy..."
ufw default deny incoming
ufw --force enable
systemctl start ufw
systemctl enable ufw

log_ok "Running system update..."
apt update
apt upgrade -yqq

SCRIPT_PATH="/usr/local/bin/update-xray-geo.sh"
XRAY_DIR="/opt/remnanode/xray/share"

log_ok "Ensuring directories..."
mkdir -p "$XRAY_DIR"

log_ok "Creating update script: $SCRIPT_PATH"
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

log_ok "Setting cron job..."
CRON_LINE="0 7 * * * /usr/local/bin/update-xray-geo.sh"
( crontab -l 2>/dev/null | grep -Fv '/usr/local/bin/update-xray-geo.sh' || true; echo "$CRON_LINE" ) | crontab -

log_ok "Running update immediately..."
"$SCRIPT_PATH"

log_ok "Done"
log_info "Scheduled daily at 07:00: /usr/local/bin/update-xray-geo.sh"