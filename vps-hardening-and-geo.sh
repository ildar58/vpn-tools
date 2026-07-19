#!/usr/bin/env bash
set -euo pipefail

log_ok(){ echo "[+] $*"; }
log_info(){ echo "[=] $*"; }
log_warn(){ echo "[!] $*"; }

[[ $EUID -eq 0 ]] || { log_warn "Run as root"; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    log_warn "Missing command: $1"
    exit 1
  }
}

ensure_ufw_rule() {
  local rule="$1"
  if ufw status | grep -Fq "$rule"; then
    log_info "UFW rule exists: $rule"
  else
    ufw $rule
  fi
}

require_cmd apt
require_cmd curl
require_cmd docker
require_cmd ufw
require_cmd systemctl
require_cmd crontab

log_ok "Applying UFW rules..."
ensure_ufw_rule "deny in 25/tcp"
ensure_ufw_rule "deny in 465/tcp"
ensure_ufw_rule "deny in 587/tcp"
ensure_ufw_rule "deny out 25/tcp"
ensure_ufw_rule "deny out 465/tcp"
ensure_ufw_rule "deny out 587/tcp"
ensure_ufw_rule "allow 22/tcp"
ensure_ufw_rule "allow 80/tcp"
ensure_ufw_rule "allow 443/tcp"
ensure_ufw_rule "allow from 84.200.193.142 to any port 2222"

ufw default deny incoming
ufw --force enable
systemctl enable --now ufw

log_ok "Updating system..."
apt update
apt upgrade -yqq

if ! command -v yq >/dev/null 2>&1; then
  log_ok "Installing Mike Farah yq..."
  ARCH=$(dpkg --print-architecture)
  case "$ARCH" in
    amd64) BIN=yq_linux_amd64;;
    arm64) BIN=yq_linux_arm64;;
    *) log_warn "Unsupported architecture: $ARCH"; exit 1;;
  esac
  curl -fsSL "https://github.com/mikefarah/yq/releases/latest/download/${BIN}" -o /usr/local/bin/yq
  chmod +x /usr/local/bin/yq
fi

XRAY_DIR="/opt/remnanode/xray/share"
SCRIPT_PATH="/usr/local/bin/update-xray-geo.sh"
COMPOSE="/opt/remnanode/docker-compose.yml"

mkdir -p "$XRAY_DIR"

cat >"$SCRIPT_PATH"<<'EOF'
#!/usr/bin/env bash
set -euo pipefail
DIR="/opt/remnanode/xray/share"
TMP=$(mktemp -d)
mkdir -p "$DIR"

curl -fsSL https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat -o "$TMP/geosite.dat"
curl -fsSL https://github.com/1andrevich/Re-filter-lists/releases/latest/download/geosite.dat -o "$TMP/refilter.dat"
curl -fsSL https://github.com/1andrevich/Re-filter-lists/releases/latest/download/geoip.dat -o "$TMP/refilter_ip.dat"

mv "$TMP/geosite.dat" "$DIR/geosite.dat"
mv "$TMP/refilter.dat" "$DIR/refilter.dat"
mv "$TMP/refilter_ip.dat" "$DIR/refilter_ip.dat"
rm -rf "$TMP"

docker restart remnanode
EOF

chmod +x "$SCRIPT_PATH"

log_ok "Updating cron..."
( crontab -l 2>/dev/null | grep -Fv "$SCRIPT_PATH" || true
  echo "0 7 * * * $SCRIPT_PATH"
) | crontab -

if [[ -f "$COMPOSE" ]]; then
  log_ok "Updating docker-compose.yml..."

  cp "$COMPOSE" "${COMPOSE}.bak"

  yq -i '
    .services.remnanode.volumes =
      ((.services.remnanode.volumes // []) +
      [
      "/opt/remnanode/xray/share/geosite.dat:/usr/local/bin/geosite.dat",
      "/opt/remnanode/xray/share/refilter_ip.dat:/usr/local/bin/refilter_ip.dat",
      "/opt/remnanode/xray/share/refilter.dat:/usr/local/bin/refilter.dat"
      ] | unique)
  ' "$COMPOSE"

  docker compose -f "$COMPOSE" config >/dev/null

  if ! cmp -s "$COMPOSE" "${COMPOSE}.bak"; then
      log_ok "docker-compose.yml changed, recreating container..."
      docker compose -f "$COMPOSE" up -d
  else
      log_info "docker-compose.yml unchanged."
  fi

  rm -f "${COMPOSE}.bak"
fi

log_ok "Running initial geo update..."
"$SCRIPT_PATH"

log_ok "Done."
