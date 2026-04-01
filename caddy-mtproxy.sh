#!/usr/bin/env bash
# ╔════════════════════════════════════════════════════════════════╗
# ║  Caddy + MTProxy Installer                                    ║
# ║  Caddy (HTTPS site on 443) + MTProxy (Fake TLS)               ║
# ║                                                                ║
# ║  Based on: selfsteal.sh by DigneZzZ & mtproxy.sh              ║
# ╚════════════════════════════════════════════════════════════════╝
# VERSION=1.0.0

SCRIPT_VERSION="1.0.0"
APP_NAME="caddy-mtproxy"

set -euo pipefail

# ============================================
# Colors
# ============================================
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly GRAY='\033[0;37m'
readonly NC='\033[0m'

# ============================================
# Configuration
# ============================================
INSTALL_DIR="/opt/caddy-mtproxy"
HTML_DIR="$INSTALL_DIR/html"
LOG_FILE="/var/log/caddy-mtproxy.log"

CADDY_CONTAINER="caddy-site"
MTPROXY_CONTAINER="mtproto-proxy"
CADDY_VERSION="2.10.2"

DEFAULT_MTPROXY_PORT=8443

# Template Registry (from selfsteal.sh)
declare -A TEMPLATE_FOLDERS=(
    ["1"]="10gag"
    ["2"]="convertit"
    ["3"]="converter"
    ["4"]="downloader"
    ["5"]="filecloud"
    ["6"]="games-site"
    ["7"]="modmanager"
    ["8"]="speedtest"
    ["9"]="YouTube"
    ["10"]="503-1"
    ["11"]="503-2"
)

declare -A TEMPLATE_NAMES=(
    ["1"]="😂 10gag - Сайт мемов"
    ["2"]="📁 Convertit - Конвертер файлов"
    ["3"]="🎬 Converter - Видеостудия-конвертер"
    ["4"]="⬇️ Downloader - Даунлоадер"
    ["5"]="☁️ FileCloud - Облачное хранилище"
    ["6"]="🎮 Games-site - Ретро игровой портал"
    ["7"]="🛠️ ModManager - Мод-менеджер для игр"
    ["8"]="🚀 SpeedTest - Спидтест"
    ["9"]="📺 YouTube - Видеохостинг с капчей"
    ["10"]="⚠️ 503 Error - Страница ошибки v1"
    ["11"]="⚠️ 503 Error - Страница ошибки v2"
)

# ============================================
# Logging
# ============================================
log_info()    { echo -e "${WHITE}ℹ️  $*${NC}"; echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*" >> "$LOG_FILE" 2>/dev/null || true; }
log_success() { echo -e "${GREEN}✅ $*${NC}"; echo "[$(date '+%Y-%m-%d %H:%M:%S')] [OK] $*" >> "$LOG_FILE" 2>/dev/null || true; }
log_warning() { echo -e "${YELLOW}⚠️  $*${NC}"; echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $*" >> "$LOG_FILE" 2>/dev/null || true; }
log_error()   { echo -e "${RED}❌ $*${NC}" >&2; echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >> "$LOG_FILE" 2>/dev/null || true; }

# ============================================
# Helpers
# ============================================
check_root() {
    if [ "${EUID:-$(id -u)}" -ne 0 ]; then
        log_error "Скрипт должен быть запущен от root (sudo)"
        exit 1
    fi
}

get_server_ip() {
    local ip
    ip=$(curl -s -4 --connect-timeout 5 ifconfig.io 2>/dev/null) || \
    ip=$(curl -s -4 --connect-timeout 5 icanhazip.com 2>/dev/null) || \
    ip=$(curl -s -4 --connect-timeout 5 ipecho.net/plain 2>/dev/null) || \
    ip="127.0.0.1"
    echo "${ip:-127.0.0.1}"
}

create_dir_safe() {
    local dir="$1"
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir" || { log_error "Не удалось создать директорию: $dir"; return 1; }
    fi
    return 0
}

# ============================================
# Docker check/install
# ============================================
ensure_docker() {
    if command -v docker &>/dev/null; then
        return 0
    fi

    log_info "Docker не найден, устанавливаю..."
    if curl -fsSL https://get.docker.com | sh >/dev/null 2>&1; then
        systemctl start docker 2>/dev/null || true
        systemctl enable docker 2>/dev/null || true
        log_success "Docker установлен"
    else
        log_error "Не удалось установить Docker"
        echo -e "${GRAY}Установите вручную: curl -fsSL https://get.docker.com | sh${NC}"
        return 1
    fi
}

ensure_docker_compose() {
    if docker compose version &>/dev/null; then
        return 0
    fi
    log_error "Docker Compose V2 не доступен"
    return 1
}

# ============================================
# DNS validation
# ============================================
validate_dns() {
    local domain="$1"
    local server_ip="$2"

    echo -e "${WHITE}🔍 Проверка DNS для ${CYAN}$domain${NC}"
    echo

    # Install dig if missing
    if ! command -v dig &>/dev/null; then
        log_info "Устанавливаю dig..."
        apt-get update -qq &>/dev/null && apt-get install -y -qq dnsutils &>/dev/null || true
    fi

    if ! command -v dig &>/dev/null; then
        log_warning "dig недоступен, пропускаю проверку DNS"
        return 0
    fi

    local a_record
    a_record=$(dig +short A "$domain" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)

    if [ -z "$a_record" ]; then
        log_warning "A-запись не найдена для $domain"
        echo -e "${GRAY}   Убедитесь, что домен настроен на IP: $server_ip${NC}"
        echo
        read -p "Продолжить без DNS? [y/N]: " -r
        [[ $REPLY =~ ^[Yy]$ ]] && return 0 || return 1
    fi

    if [ "$a_record" = "$server_ip" ]; then
        log_success "DNS: $domain → $a_record (совпадает с сервером)"
        return 0
    else
        log_warning "DNS: $domain → $a_record (ожидалось: $server_ip)"
        echo
        read -p "IP не совпадает. Продолжить? [y/N]: " -r
        [[ $REPLY =~ ^[Yy]$ ]] && return 0 || return 1
    fi
}

# ============================================
# MTProxy secret generation
# ============================================
generate_mtproxy_secret() {
    local domain="$1"

    # Ensure xxd is available
    if ! command -v xxd &>/dev/null; then
        apt-get install -y -qq xxd 2>/dev/null || apt-get install -y -qq vim-common 2>/dev/null || true
    fi

    local domain_hex
    domain_hex=$(echo -n "$domain" | xxd -ps | tr -d '\n')

    # Pad with random hex to 30 chars total
    local domain_len=${#domain_hex}
    local needed=$((30 - domain_len))

    if [ "$needed" -gt 0 ]; then
        local random_hex
        random_hex=$(openssl rand -hex 15 | cut -c1-"$needed")
        echo "ee${domain_hex}${random_hex}"
    else
        # Domain hex is already >= 30 chars, truncate
        echo "ee${domain_hex:0:30}"
    fi
}

# ============================================
# Template downloading (from selfsteal.sh)
# ============================================
download_template() {
    local template_type="$1"
    local template_folder="${TEMPLATE_FOLDERS[$template_type]:-}"
    local template_name="${TEMPLATE_NAMES[$template_type]:-}"

    if [ -z "$template_folder" ]; then
        log_error "Неизвестный шаблон: $template_type"
        return 1
    fi

    echo -e "${WHITE}🎨 Загрузка шаблона: $template_name${NC}"
    echo

    create_dir_safe "$HTML_DIR" || return 1
    rm -rf "${HTML_DIR:?}"/* 2>/dev/null || true
    cd "$HTML_DIR" || return 1

    # Method 1: git sparse-checkout
    if command -v git &>/dev/null; then
        local temp_dir="/tmp/caddy-mtproxy-tpl-$$"
        if git clone --filter=blob:none --sparse "https://github.com/DigneZzZ/remnawave-scripts.git" "$temp_dir" 2>/dev/null; then
            cd "$temp_dir"
            git sparse-checkout set "sni-templates/$template_folder" 2>/dev/null
            local src="$temp_dir/sni-templates/$template_folder"
            if [ -d "$src" ] && cp -r "$src"/* "$HTML_DIR/" 2>/dev/null; then
                local count
                count=$(find "$HTML_DIR" -type f | wc -l)
                log_success "Шаблон загружен ($count файлов)"
                rm -rf "$temp_dir"
                cd "$HTML_DIR"
                chmod -R 644 "$HTML_DIR"/* 2>/dev/null || true
                find "$HTML_DIR" -type d -exec chmod 755 {} \; 2>/dev/null || true
                return 0
            fi
            rm -rf "$temp_dir"
            cd "$HTML_DIR"
        fi
    fi

    # Method 2: GitHub API + curl
    local api_url="https://api.github.com/repos/DigneZzZ/remnawave-scripts/git/trees/main?recursive=1"
    local tree_data
    tree_data=$(curl -s "$api_url" 2>/dev/null)

    if echo "$tree_data" | grep -q '"path"'; then
        local files
        files=$(echo "$tree_data" | grep -o '"path":[^,]*' | sed 's/"path":"//' | sed 's/"//' | grep "^sni-templates/$template_folder/")
        local count=0

        while IFS= read -r fpath; do
            [ -z "$fpath" ] && continue
            local rel="${fpath#sni-templates/$template_folder/}"
            local url="https://raw.githubusercontent.com/DigneZzZ/remnawave-scripts/main/$fpath"
            local dir
            dir=$(dirname "$rel")
            [ "$dir" != "." ] && mkdir -p "$dir"
            if curl -fsSL "$url" -o "$rel" 2>/dev/null; then
                ((count++))
            fi
        done <<< "$files"

        if [ "$count" -gt 0 ]; then
            log_success "Шаблон загружен ($count файлов)"
            chmod -R 644 "$HTML_DIR"/* 2>/dev/null || true
            find "$HTML_DIR" -type d -exec chmod 755 {} \; 2>/dev/null || true
            return 0
        fi
    fi

    # Method 3: Fallback HTML
    log_warning "Не удалось загрузить шаблон, создаю заглушку"
    create_fallback_html "$template_name"
    return 0
}

create_fallback_html() {
    local name="${1:-Service}"
    cat > "$HTML_DIR/index.html" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$name</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh; display: flex; align-items: center; justify-content: center; color: white;
        }
        .container { text-align: center; max-width: 600px; padding: 2rem; }
        h1 { font-size: 3rem; margin-bottom: 1rem; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }
        p { font-size: 1.2rem; opacity: 0.9; margin-bottom: 2rem; }
        .status { background: rgba(255,255,255,0.1); padding: 1rem 2rem; border-radius: 10px; backdrop-filter: blur(10px); }
    </style>
</head>
<body>
    <div class="container">
        <h1>Service Ready</h1>
        <p>$name is now active</p>
        <div class="status"><p>System Online</p></div>
    </div>
</body>
</html>
EOF
}

# ============================================
# Caddyfile generation
# ============================================
create_caddyfile() {
    local domain="$1"

    cat > "$INSTALL_DIR/Caddyfile" << EOF
{
    log {
        output file /var/log/caddy/access.log {
            roll_size 10MB
            roll_keep 5
            roll_keep_for 720h
        }
        level ERROR
        format json
    }
}

${domain} {
    root * /var/www/html
    file_server
    encode zstd gzip

    header {
        X-Content-Type-Options "nosniff"
        X-Frame-Options "SAMEORIGIN"
        X-XSS-Protection "1; mode=block"
        -Server
    }

    @static {
        path *.css *.js *.png *.jpg *.jpeg *.gif *.ico *.svg *.woff *.woff2 *.ttf *.eot
    }
    header @static Cache-Control "public, max-age=2592000, immutable"

    try_files {path} /index.html

    log {
        output file /var/log/caddy/access.log {
            roll_size 10MB
            roll_keep 5
        }
        level ERROR
    }
}
EOF
    log_success "Caddyfile создан"
}

# ============================================
# Docker Compose generation
# ============================================
create_docker_compose() {
    local domain="$1"
    local mtproxy_port="$2"
    local secret="$3"
    local tag="${4:-}"

    local tag_env=""
    if [ -n "$tag" ]; then
        tag_env="      TAG: \"$tag\""
    fi

    cat > "$INSTALL_DIR/docker-compose.yml" << EOF
services:
  caddy:
    image: caddy:${CADDY_VERSION}
    container_name: ${CADDY_CONTAINER}
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - ${HTML_DIR}:/var/www/html:ro
      - ./logs/caddy:/var/log/caddy
      - caddy_data:/data
      - caddy_config:/config
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  mtproto-proxy:
    image: telegrammessenger/proxy:latest
    container_name: ${MTPROXY_CONTAINER}
    restart: unless-stopped
    ports:
      - "${mtproxy_port}:443"
    environment:
      SECRET: "${secret}"
${tag_env}
    volumes:
      - mtproxy_config:/data
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

volumes:
  caddy_data:
  caddy_config:
  mtproxy_config:
EOF
    log_success "docker-compose.yml создан"
}

# ============================================
# .env / info file
# ============================================
save_config() {
    local domain="$1"
    local mtproxy_port="$2"
    local secret="$3"
    local server_ip="$4"
    local tag="${5:-}"

    cat > "$INSTALL_DIR/.env" << EOF
DOMAIN=$domain
MTPROXY_PORT=$mtproxy_port
SECRET=$secret
SERVER_IP=$server_ip
TAG=$tag
INSTALLED=$(date '+%Y-%m-%d %H:%M:%S')
EOF

    local proxy_link="tg://proxy?server=${server_ip}&port=${mtproxy_port}&secret=${secret}"
    local web_link="https://t.me/proxy?server=${server_ip}&port=${mtproxy_port}&secret=${secret}"

    cat > "$INSTALL_DIR/info.txt" << EOF
═══════════════════════════════════════════
  Caddy + MTProxy Configuration
═══════════════════════════════════════════

🌐 Сайт:     https://${domain}
🔌 MTProxy:   ${server_ip}:${mtproxy_port}
🔑 Секрет:    ${secret}
🏷️  TAG:       ${tag:-не задан}

📱 Ссылка для Telegram:
   ${proxy_link}

🌐 Web ссылка:
   ${web_link}

📅 Установлено: $(date)
═══════════════════════════════════════════
EOF
}

# ============================================
# INSTALL
# ============================================
install_command() {
    check_root
    clear

    echo -e "${WHITE}🚀 Установка Caddy + MTProxy${NC}"
    echo -e "${GRAY}$(printf '─%.0s' $(seq 1 50))${NC}"
    echo -e "${CYAN}Caddy (HTTPS сайт на 443) + MTProxy (Fake TLS)${NC}"
    echo

    # Check existing installation
    if [ -f "$INSTALL_DIR/docker-compose.yml" ]; then
        log_warning "Обнаружена существующая установка!"
        echo
        echo -e "${WHITE}Варианты:${NC}"
        echo -e "   ${WHITE}1)${NC} ${GRAY}Переустановить${NC}"
        echo -e "   ${WHITE}2)${NC} ${GRAY}Отмена${NC}"
        echo
        read -p "Выберите [1-2]: " choice
        case "$choice" in
            1)
                log_info "Останавливаю старые сервисы..."
                cd "$INSTALL_DIR" && docker compose down 2>/dev/null || true
                ;;
            *)
                echo -e "${GRAY}Отменено${NC}"
                return 0
                ;;
        esac
        echo
    fi

    # Check requirements
    echo -e "${WHITE}🔍 Проверка системы${NC}"
    echo -e "${GRAY}$(printf '─%.0s' $(seq 1 40))${NC}"
    ensure_docker || return 1
    ensure_docker_compose || return 1
    echo -e "${GREEN}✅ Docker и Compose доступны${NC}"
    echo

    # Get server IP
    local server_ip
    server_ip=$(get_server_ip)
    echo -e "${WHITE}🖥️  IP сервера: ${CYAN}$server_ip${NC}"
    echo

    # Domain input
    echo -e "${WHITE}🌐 Настройка домена${NC}"
    echo -e "${GRAY}$(printf '─%.0s' $(seq 1 40))${NC}"
    echo -e "${GRAY}Caddy автоматически получит SSL-сертификат Let's Encrypt${NC}"
    echo -e "${GRAY}MTProxy Fake TLS будет имитировать этот же домен${NC}"
    echo

    local domain=""
    while [ -z "$domain" ]; do
        read -p "Введите домен (напр. mt.example.com): " domain
        if [ -z "$domain" ]; then
            log_error "Домен не может быть пустым"
            continue
        fi
        # Basic format check
        if ! [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
            log_error "Неверный формат домена"
            domain=""
            continue
        fi
    done

    echo
    validate_dns "$domain" "$server_ip" || return 1
    echo

    # MTProxy port
    echo -e "${WHITE}🔌 Настройка MTProxy${NC}"
    echo -e "${GRAY}$(printf '─%.0s' $(seq 1 40))${NC}"
    echo -e "${GRAY}Порт 443 занят Caddy. MTProxy будет на отдельном порту.${NC}"
    echo

    local mtproxy_port
    read -p "Порт для MTProxy (по умолчанию: $DEFAULT_MTPROXY_PORT): " mtproxy_port
    mtproxy_port=${mtproxy_port:-$DEFAULT_MTPROXY_PORT}

    if ! [[ "$mtproxy_port" =~ ^[0-9]+$ ]] || [ "$mtproxy_port" -lt 1 ] || [ "$mtproxy_port" -gt 65535 ]; then
        log_error "Неверный номер порта"
        return 1
    fi

    if [ "$mtproxy_port" = "443" ] || [ "$mtproxy_port" = "80" ]; then
        log_error "Порты 80 и 443 заняты Caddy!"
        return 1
    fi

    # Check port availability
    if ss -tuln | grep -q ":${mtproxy_port} "; then
        log_warning "Порт $mtproxy_port уже занят!"
        read -p "Продолжить? [y/N]: " -r
        [[ ! $REPLY =~ ^[Yy]$ ]] && return 1
    fi

    # Generate MTProxy secret
    echo
    log_info "Генерация Fake TLS секрета для домена $domain..."
    local secret
    secret=$(generate_mtproxy_secret "$domain")
    echo -e "${WHITE}   Секрет: ${YELLOW}$secret${NC}"
    echo -e "${GRAY}   (Fake TLS имитирует подключение к $domain)${NC}"

    # TAG (optional)
    echo
    echo -e "${WHITE}🏷️  TAG от @MTProxybot (опционально)${NC}"
    echo -e "${GRAY}Для продвижения канала. Можно добавить позже.${NC}"
    echo
    read -p "Введите TAG (оставьте пустым для пропуска): " user_tag

    if [ -n "$user_tag" ]; then
        if [[ ! "$user_tag" =~ ^[0-9a-fA-F]{32}$ ]]; then
            log_warning "Неверный формат TAG (ожидается 32 hex символа). Пропускаю."
            user_tag=""
        fi
    fi

    # Template selection
    echo
    echo -e "${WHITE}🎨 Выбор шаблона сайта${NC}"
    echo -e "${GRAY}$(printf '─%.0s' $(seq 1 40))${NC}"
    echo
    for i in $(seq 1 11); do
        printf "   ${WHITE}%-3s${NC} ${CYAN}%s${NC}\n" "$i)" "${TEMPLATE_NAMES[$i]}"
    done
    echo -e "   ${WHITE}r)${NC}  ${GRAY}🎲 Случайный${NC}"
    echo

    local template_choice
    read -p "Выберите шаблон [1-11, r]: " template_choice

    local template_id
    if [ "$template_choice" = "r" ] || [ "$template_choice" = "R" ]; then
        template_id=$((RANDOM % 11 + 1))
        echo -e "${CYAN}🎲 Случайный выбор: ${TEMPLATE_NAMES[$template_id]}${NC}"
    elif [[ "$template_choice" =~ ^[1-9]$|^1[01]$ ]]; then
        template_id="$template_choice"
    else
        template_id=$((RANDOM % 11 + 1))
        echo -e "${CYAN}🎲 Случайный выбор: ${TEMPLATE_NAMES[$template_id]}${NC}"
    fi

    # Summary
    echo
    echo -e "${WHITE}📋 Итого${NC}"
    echo -e "${GRAY}$(printf '─%.0s' $(seq 1 40))${NC}"
    printf "   ${WHITE}%-20s${NC} ${GRAY}%s${NC}\n" "Домен:" "$domain"
    printf "   ${WHITE}%-20s${NC} ${GRAY}%s${NC}\n" "Сайт (Caddy):" "https://$domain (порт 443)"
    printf "   ${WHITE}%-20s${NC} ${GRAY}%s${NC}\n" "MTProxy порт:" "$mtproxy_port"
    printf "   ${WHITE}%-20s${NC} ${GRAY}%s${NC}\n" "Fake TLS домен:" "$domain"
    printf "   ${WHITE}%-20s${NC} ${GRAY}%s${NC}\n" "Шаблон:" "${TEMPLATE_NAMES[$template_id]}"
    printf "   ${WHITE}%-20s${NC} ${GRAY}%s${NC}\n" "TAG:" "${user_tag:-не задан}"
    printf "   ${WHITE}%-20s${NC} ${GRAY}%s${NC}\n" "Установка в:" "$INSTALL_DIR"
    echo

    read -p "Начать установку? [Y/n]: " -r
    [[ $REPLY =~ ^[Nn]$ ]] && { echo -e "${GRAY}Отменено${NC}"; return 0; }

    # Create directories
    echo
    echo -e "${WHITE}📁 Создание директорий${NC}"
    create_dir_safe "$INSTALL_DIR" || return 1
    create_dir_safe "$HTML_DIR" || return 1
    create_dir_safe "$INSTALL_DIR/logs/caddy" || return 1
    log_success "Директории созданы"

    # Download template
    echo
    download_template "$template_id"

    # Create configs
    echo
    echo -e "${WHITE}⚙️  Создание конфигурации${NC}"
    echo -e "${GRAY}$(printf '─%.0s' $(seq 1 40))${NC}"
    create_caddyfile "$domain"
    create_docker_compose "$domain" "$mtproxy_port" "$secret" "$user_tag"
    save_config "$domain" "$mtproxy_port" "$secret" "$server_ip" "$user_tag"

    # Open firewall ports
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        log_info "Открываю порты в UFW..."
        ufw allow 80/tcp 2>/dev/null || true
        ufw allow 443/tcp 2>/dev/null || true
        ufw allow "$mtproxy_port"/tcp 2>/dev/null || true
        log_success "Порты 80, 443, $mtproxy_port открыты в UFW"
    fi

    # Start services
    echo
    echo -e "${WHITE}🚀 Запуск сервисов${NC}"
    echo -e "${GRAY}$(printf '─%.0s' $(seq 1 40))${NC}"
    cd "$INSTALL_DIR"

    if docker compose up -d; then
        log_success "Сервисы запущены!"
    else
        log_error "Ошибка запуска сервисов"
        docker compose logs
        return 1
    fi

    # Wait and verify
    echo
    log_info "Ожидание запуска контейнеров..."
    sleep 5

    local caddy_ok=false
    local mtproxy_ok=false

    if docker ps --format '{{.Names}}' | grep -q "$CADDY_CONTAINER"; then
        caddy_ok=true
    fi
    if docker ps --format '{{.Names}}' | grep -q "$MTPROXY_CONTAINER"; then
        mtproxy_ok=true
    fi

    echo

    # Install management script
    install_management_script

    # Final output
    local proxy_link="tg://proxy?server=${server_ip}&port=${mtproxy_port}&secret=${secret}"
    local web_link="https://t.me/proxy?server=${server_ip}&port=${mtproxy_port}&secret=${secret}"

    echo
    echo -e "${GRAY}$(printf '═%.0s' $(seq 1 55))${NC}"
    echo -e "${WHITE}  🎉 Установка завершена!${NC}"
    echo -e "${GRAY}$(printf '═%.0s' $(seq 1 55))${NC}"
    echo

    if [ "$caddy_ok" = true ]; then
        echo -e "  ${GREEN}✅ Caddy:${NC}    работает"
    else
        echo -e "  ${RED}❌ Caddy:${NC}    не запустился"
    fi
    if [ "$mtproxy_ok" = true ]; then
        echo -e "  ${GREEN}✅ MTProxy:${NC}  работает"
    else
        echo -e "  ${RED}❌ MTProxy:${NC}  не запустился"
    fi

    echo
    echo -e "  ${WHITE}🌐 Сайт:${NC}     https://$domain"
    echo -e "  ${WHITE}🔌 MTProxy:${NC}   $server_ip:$mtproxy_port"
    echo -e "  ${WHITE}🔑 Секрет:${NC}    $secret"
    echo

    echo -e "  ${WHITE}📱 Telegram ссылка:${NC}"
    echo -e "  ${GREEN}$proxy_link${NC}"
    echo
    echo -e "  ${WHITE}🌐 Web ссылка:${NC}"
    echo -e "  ${GREEN}$web_link${NC}"
    echo
    echo -e "${GRAY}$(printf '═%.0s' $(seq 1 55))${NC}"
    echo
    echo -e "${WHITE}Управление:${NC} ${CYAN}$APP_NAME${NC} (интерактивное меню)"
    echo -e "${WHITE}Конфигурация:${NC} ${GRAY}$INSTALL_DIR/info.txt${NC}"
    echo
}

# ============================================
# Management script installer
# ============================================
install_management_script() {
    local target="/usr/local/bin/$APP_NAME"

    if [ -f "$0" ] && [ "$0" != "bash" ]; then
        local src
        src=$(realpath "$0" 2>/dev/null || readlink -f "$0" 2>/dev/null || echo "$0")
        local tgt
        tgt=$(realpath "$target" 2>/dev/null || echo "$target")

        if [ "$src" = "$tgt" ]; then
            return 0
        fi

        if [ -f "$src" ]; then
            cp "$src" "$target" 2>/dev/null || true
            chmod +x "$target" 2>/dev/null || true
            log_success "Утилита управления: $target"
        fi
    fi
}

# ============================================
# UP / DOWN / RESTART
# ============================================
up_command() {
    check_root
    if [ ! -f "$INSTALL_DIR/docker-compose.yml" ]; then
        log_error "Не установлено. Сначала запустите: $APP_NAME install"
        return 1
    fi
    log_info "Запуск сервисов..."
    cd "$INSTALL_DIR" && docker compose up -d
    log_success "Сервисы запущены"
}

down_command() {
    check_root
    if [ ! -f "$INSTALL_DIR/docker-compose.yml" ]; then
        log_warning "Не установлено"
        return 0
    fi
    log_info "Остановка сервисов..."
    cd "$INSTALL_DIR" && docker compose down
    log_success "Сервисы остановлены"
}

restart_command() {
    check_root
    log_info "Перезапуск сервисов..."
    down_command
    sleep 2
    up_command
}

# ============================================
# STATUS
# ============================================
status_command() {
    if [ ! -d "$INSTALL_DIR" ]; then
        log_error "Не установлено"
        return 1
    fi

    echo -e "${WHITE}📊 Статус сервисов${NC}"
    echo -e "${GRAY}$(printf '─%.0s' $(seq 1 40))${NC}"
    echo

    cd "$INSTALL_DIR"

    # Caddy status
    local caddy_state
    caddy_state=$(docker inspect -f '{{.State.Status}}' "$CADDY_CONTAINER" 2>/dev/null || echo "не найден")
    case "$caddy_state" in
        running)   echo -e "  ${GREEN}✅ Caddy:${NC}    работает" ;;
        restarting) echo -e "  ${YELLOW}⚠️  Caddy:${NC}    перезапускается (ошибка)" ;;
        *)         echo -e "  ${RED}❌ Caddy:${NC}    $caddy_state" ;;
    esac

    # MTProxy status
    local mtproxy_state
    mtproxy_state=$(docker inspect -f '{{.State.Status}}' "$MTPROXY_CONTAINER" 2>/dev/null || echo "не найден")
    case "$mtproxy_state" in
        running)   echo -e "  ${GREEN}✅ MTProxy:${NC}  работает" ;;
        restarting) echo -e "  ${YELLOW}⚠️  MTProxy:${NC}  перезапускается (ошибка)" ;;
        *)         echo -e "  ${RED}❌ MTProxy:${NC}  $mtproxy_state" ;;
    esac

    # Config info
    if [ -f "$INSTALL_DIR/.env" ]; then
        echo
        echo -e "${WHITE}⚙️  Конфигурация:${NC}"

        local domain port secret server_ip tag
        domain=$(grep "^DOMAIN=" "$INSTALL_DIR/.env" | cut -d'=' -f2)
        port=$(grep "^MTPROXY_PORT=" "$INSTALL_DIR/.env" | cut -d'=' -f2)
        secret=$(grep "^SECRET=" "$INSTALL_DIR/.env" | cut -d'=' -f2)
        server_ip=$(grep "^SERVER_IP=" "$INSTALL_DIR/.env" | cut -d'=' -f2)
        tag=$(grep "^TAG=" "$INSTALL_DIR/.env" | cut -d'=' -f2)

        printf "   ${WHITE}%-15s${NC} ${GRAY}%s${NC}\n" "Домен:" "$domain"
        printf "   ${WHITE}%-15s${NC} ${GRAY}%s${NC}\n" "Сайт:" "https://$domain"
        printf "   ${WHITE}%-15s${NC} ${GRAY}%s${NC}\n" "MTProxy:" "${server_ip}:${port}"
        printf "   ${WHITE}%-15s${NC} ${GRAY}%s${NC}\n" "Секрет:" "$secret"

        if [ -n "$tag" ]; then
            printf "   ${WHITE}%-15s${NC} ${GRAY}%s${NC}\n" "TAG:" "$tag"
        fi

        if [ -n "$secret" ] && [ -n "$server_ip" ] && [ -n "$port" ]; then
            echo
            echo -e "${WHITE}📱 Telegram ссылка:${NC}"
            echo -e "${GREEN}   tg://proxy?server=${server_ip}&port=${port}&secret=${secret}${NC}"
        fi
    fi

    echo
}

# ============================================
# LOGS
# ============================================
logs_command() {
    if [ ! -f "$INSTALL_DIR/docker-compose.yml" ]; then
        log_error "Не установлено"
        return 1
    fi

    echo -e "${WHITE}📝 Логи (Ctrl+C для выхода)${NC}"
    echo
    echo -e "${WHITE}Какие логи показать?${NC}"
    echo -e "   ${WHITE}1)${NC} ${GRAY}Все${NC}"
    echo -e "   ${WHITE}2)${NC} ${GRAY}Только Caddy${NC}"
    echo -e "   ${WHITE}3)${NC} ${GRAY}Только MTProxy${NC}"
    echo
    read -p "Выберите [1-3]: " choice

    cd "$INSTALL_DIR"
    case "$choice" in
        2) docker compose logs -f caddy ;;
        3) docker compose logs -f mtproto-proxy ;;
        *) docker compose logs -f ;;
    esac
}

# ============================================
# TEMPLATE
# ============================================
template_command() {
    check_root

    if [ ! -d "$INSTALL_DIR" ]; then
        log_error "Не установлено"
        return 1
    fi

    while true; do
        clear
        echo -e "${WHITE}🎨 Управление шаблонами${NC}"
        echo -e "${GRAY}$(printf '─%.0s' $(seq 1 40))${NC}"
        echo

        for i in $(seq 1 11); do
            printf "   ${WHITE}%-3s${NC} ${CYAN}%s${NC}\n" "$i)" "${TEMPLATE_NAMES[$i]}"
        done
        echo
        echo -e "   ${WHITE}r)${NC}  ${GRAY}🎲 Случайный${NC}"
        echo -e "   ${WHITE}v)${NC}  ${GRAY}📄 Текущий шаблон${NC}"
        echo -e "   ${WHITE}0)${NC}  ${GRAY}⬅️  Назад${NC}"
        echo

        read -p "Выберите [0-11, r, v]: " choice

        case "$choice" in
            [1-9]|10|11)
                echo
                if download_template "$choice"; then
                    log_success "Шаблон установлен!"
                    echo
                    read -p "Перезапустить Caddy? [Y/n]: " -r
                    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
                        cd "$INSTALL_DIR" && docker compose restart caddy
                        log_success "Caddy перезапущен"
                    fi
                fi
                read -p "Нажмите Enter..."
                ;;
            r|R)
                local rid=$((RANDOM % 11 + 1))
                echo -e "${CYAN}🎲 Случайный: ${TEMPLATE_NAMES[$rid]}${NC}"
                echo
                download_template "$rid"
                cd "$INSTALL_DIR" && docker compose restart caddy 2>/dev/null || true
                read -p "Нажмите Enter..."
                ;;
            v|V)
                echo
                if [ -f "$HTML_DIR/index.html" ]; then
                    local title
                    title=$(grep -o '<title>[^<]*</title>' "$HTML_DIR/index.html" 2>/dev/null | sed 's/<title>\|<\/title>//g' | head -1)
                    local fcount
                    fcount=$(find "$HTML_DIR" -type f | wc -l)
                    local fsize
                    fsize=$(du -sh "$HTML_DIR" 2>/dev/null | cut -f1)
                    echo -e "${WHITE}   Title:${NC} ${GRAY}${title:-Unknown}${NC}"
                    echo -e "${WHITE}   Файлов:${NC} ${GRAY}$fcount${NC}"
                    echo -e "${WHITE}   Размер:${NC} ${GRAY}$fsize${NC}"
                    echo -e "${WHITE}   Путь:${NC} ${GRAY}$HTML_DIR${NC}"
                else
                    echo -e "${GRAY}   Шаблон не установлен${NC}"
                fi
                echo
                read -p "Нажмите Enter..."
                ;;
            0) return 0 ;;
            *) log_error "Неверный выбор"; sleep 1 ;;
        esac
    done
}

# ============================================
# UPDATE TAG
# ============================================
update_tag_command() {
    check_root

    if [ ! -f "$INSTALL_DIR/.env" ]; then
        log_error "Не установлено"
        return 1
    fi

    echo -e "${WHITE}🏷️  Обновление TAG от @MTProxybot${NC}"
    echo -e "${GRAY}$(printf '─%.0s' $(seq 1 40))${NC}"
    echo
    echo -e "${CYAN}Как получить TAG:${NC}"
    echo -e "${GRAY}1. Откройте @MTProxybot в Telegram${NC}"
    echo -e "${GRAY}2. Отправьте /newproxy${NC}"
    echo -e "${GRAY}3. Зарегистрируйте прокси${NC}"
    echo -e "${GRAY}4. Бот выдаст TAG (32 hex символа)${NC}"
    echo

    read -p "Введите TAG (пусто для удаления): " new_tag

    if [ -n "$new_tag" ]; then
        if [[ ! "$new_tag" =~ ^[0-9a-fA-F]{32}$ ]]; then
            log_error "Неверный формат TAG"
            return 1
        fi
        sed -i "s/^TAG=.*/TAG=$new_tag/" "$INSTALL_DIR/.env"
        log_success "TAG обновлён: $new_tag"
    else
        sed -i "s/^TAG=.*/TAG=/" "$INSTALL_DIR/.env"
        log_success "TAG удалён"
    fi

    # Regenerate docker-compose with new TAG
    local domain port secret server_ip
    domain=$(grep "^DOMAIN=" "$INSTALL_DIR/.env" | cut -d'=' -f2)
    port=$(grep "^MTPROXY_PORT=" "$INSTALL_DIR/.env" | cut -d'=' -f2)
    secret=$(grep "^SECRET=" "$INSTALL_DIR/.env" | cut -d'=' -f2)
    server_ip=$(grep "^SERVER_IP=" "$INSTALL_DIR/.env" | cut -d'=' -f2)

    create_docker_compose "$domain" "$port" "$secret" "$new_tag"

    echo
    log_info "Перезапуск MTProxy..."
    cd "$INSTALL_DIR" && docker compose up -d mtproto-proxy
    log_success "MTProxy перезапущен с новым TAG"
}

# ============================================
# EDIT
# ============================================
edit_command() {
    check_root

    if [ ! -d "$INSTALL_DIR" ]; then
        log_error "Не установлено"
        return 1
    fi

    echo -e "${WHITE}✏️  Редактирование конфигурации${NC}"
    echo -e "${GRAY}$(printf '─%.0s' $(seq 1 40))${NC}"
    echo
    echo -e "   ${WHITE}1)${NC} ${GRAY}Caddyfile${NC}"
    echo -e "   ${WHITE}2)${NC} ${GRAY}docker-compose.yml${NC}"
    echo -e "   ${WHITE}3)${NC} ${GRAY}.env (параметры)${NC}"
    echo -e "   ${WHITE}0)${NC} ${GRAY}Отмена${NC}"
    echo

    read -p "Выберите [0-3]: " choice

    case "$choice" in
        1)
            ${EDITOR:-nano} "$INSTALL_DIR/Caddyfile"
            log_warning "Перезапустите для применения: $APP_NAME restart"
            ;;
        2)
            ${EDITOR:-nano} "$INSTALL_DIR/docker-compose.yml"
            log_warning "Перезапустите для применения: $APP_NAME restart"
            ;;
        3)
            ${EDITOR:-nano} "$INSTALL_DIR/.env"
            log_warning "Перезапустите для применения: $APP_NAME restart"
            ;;
        *) echo -e "${GRAY}Отменено${NC}" ;;
    esac
}

# ============================================
# UNINSTALL
# ============================================
uninstall_command() {
    check_root

    echo -e "${WHITE}🗑️  Удаление Caddy + MTProxy${NC}"
    echo -e "${GRAY}$(printf '─%.0s' $(seq 1 40))${NC}"
    echo

    if [ ! -d "$INSTALL_DIR" ]; then
        log_warning "Не установлено"
        return 0
    fi

    log_warning "Это полностью удалит Caddy + MTProxy и все данные!"
    echo
    read -p "Вы уверены? (введите YES): " confirm

    if [ "$confirm" != "YES" ]; then
        echo -e "${GRAY}Отменено${NC}"
        return 0
    fi

    echo
    log_info "Остановка сервисов..."
    cd "$INSTALL_DIR" && docker compose down -v 2>/dev/null || true

    log_info "Удаление Docker образов..."
    docker rmi "caddy:${CADDY_VERSION}" 2>/dev/null || true
    docker rmi telegrammessenger/proxy:latest 2>/dev/null || true

    log_info "Удаление файлов..."
    rm -rf "$INSTALL_DIR"

    log_info "Удаление утилиты управления..."
    rm -f "/usr/local/bin/$APP_NAME"

    echo
    log_success "Caddy + MTProxy полностью удалены"
}

# ============================================
# SHOW LINKS
# ============================================
links_command() {
    if [ ! -f "$INSTALL_DIR/.env" ]; then
        log_error "Не установлено"
        return 1
    fi

    local domain port secret server_ip
    domain=$(grep "^DOMAIN=" "$INSTALL_DIR/.env" | cut -d'=' -f2)
    port=$(grep "^MTPROXY_PORT=" "$INSTALL_DIR/.env" | cut -d'=' -f2)
    secret=$(grep "^SECRET=" "$INSTALL_DIR/.env" | cut -d'=' -f2)
    server_ip=$(grep "^SERVER_IP=" "$INSTALL_DIR/.env" | cut -d'=' -f2)

    local proxy_link="tg://proxy?server=${server_ip}&port=${port}&secret=${secret}"
    local web_link="https://t.me/proxy?server=${server_ip}&port=${port}&secret=${secret}"

    echo
    echo -e "${WHITE}🔗 Ссылки для подключения${NC}"
    echo -e "${GRAY}$(printf '═%.0s' $(seq 1 55))${NC}"
    echo
    echo -e "  ${WHITE}🌐 Сайт:${NC}      https://$domain"
    echo
    echo -e "  ${WHITE}📱 Telegram:${NC}"
    echo -e "  ${GREEN}$proxy_link${NC}"
    echo
    echo -e "  ${WHITE}🌐 Web:${NC}"
    echo -e "  ${GREEN}$web_link${NC}"
    echo
    echo -e "  ${WHITE}🔑 Секрет:${NC}     $secret"
    echo -e "  ${WHITE}🔌 Порт:${NC}       $port"
    echo -e "  ${WHITE}🖥️  Сервер:${NC}     $server_ip"
    echo
    echo -e "${GRAY}$(printf '═%.0s' $(seq 1 55))${NC}"
    echo
}

# ============================================
# HELP
# ============================================
show_help() {
    echo -e "${WHITE}Caddy + MTProxy Management v$SCRIPT_VERSION${NC}"
    echo
    echo -e "${WHITE}Использование:${NC}"
    echo -e "  ${CYAN}$APP_NAME${NC} [${GRAY}команда${NC}]"
    echo
    echo -e "${WHITE}Команды:${NC}"
    printf "   ${CYAN}%-14s${NC} %s\n" "install"    "🚀 Установить Caddy + MTProxy"
    printf "   ${CYAN}%-14s${NC} %s\n" "up"         "▶️  Запустить сервисы"
    printf "   ${CYAN}%-14s${NC} %s\n" "down"       "⏹️  Остановить сервисы"
    printf "   ${CYAN}%-14s${NC} %s\n" "restart"    "🔄 Перезапустить сервисы"
    printf "   ${CYAN}%-14s${NC} %s\n" "status"     "📊 Статус сервисов"
    printf "   ${CYAN}%-14s${NC} %s\n" "logs"       "📝 Просмотр логов"
    printf "   ${CYAN}%-14s${NC} %s\n" "links"      "🔗 Показать ссылки для подключения"
    printf "   ${CYAN}%-14s${NC} %s\n" "template"   "🎨 Управление шаблонами сайта"
    printf "   ${CYAN}%-14s${NC} %s\n" "update-tag" "🏷️  Обновить TAG от @MTProxybot"
    printf "   ${CYAN}%-14s${NC} %s\n" "edit"       "✏️  Редактировать конфигурацию"
    printf "   ${CYAN}%-14s${NC} %s\n" "uninstall"  "🗑️  Полное удаление"
    printf "   ${CYAN}%-14s${NC} %s\n" "menu"       "📋 Интерактивное меню"
    printf "   ${CYAN}%-14s${NC} %s\n" "help"       "❓ Эта справка"
    echo
    echo -e "${WHITE}Архитектура:${NC}"
    echo -e "  ${GRAY}Caddy на порту 443 — полноценный HTTPS-сайт с Let's Encrypt${NC}"
    echo -e "  ${GRAY}MTProxy на отдельном порту — Fake TLS имитирует ваш сайт${NC}"
    echo
}

# ============================================
# INTERACTIVE MENU
# ============================================
main_menu() {
    while true; do
        clear
        echo -e "${WHITE}🔗 Caddy + MTProxy${NC}"
        echo -e "${GRAY}Управление v$SCRIPT_VERSION${NC}"
        echo -e "${GRAY}$(printf '─%.0s' $(seq 1 40))${NC}"
        echo

        # Quick status
        if [ -d "$INSTALL_DIR" ] && [ -f "$INSTALL_DIR/docker-compose.yml" ]; then
            local c_state m_state
            c_state=$(docker inspect -f '{{.State.Status}}' "$CADDY_CONTAINER" 2>/dev/null || echo "off")
            m_state=$(docker inspect -f '{{.State.Status}}' "$MTPROXY_CONTAINER" 2>/dev/null || echo "off")

            local c_icon m_icon
            [ "$c_state" = "running" ] && c_icon="${GREEN}●${NC}" || c_icon="${RED}●${NC}"
            [ "$m_state" = "running" ] && m_icon="${GREEN}●${NC}" || m_icon="${RED}●${NC}"

            echo -e "  ${c_icon} Caddy: $c_state    ${m_icon} MTProxy: $m_state"

            local domain=""
            if [ -f "$INSTALL_DIR/.env" ]; then
                domain=$(grep "^DOMAIN=" "$INSTALL_DIR/.env" | cut -d'=' -f2)
                [ -n "$domain" ] && echo -e "  ${GRAY}https://$domain${NC}"
            fi
        else
            echo -e "  ${GRAY}📦 Не установлено${NC}"
        fi

        echo
        echo -e "${WHITE}🔧 Сервисы:${NC}"
        echo -e "   ${WHITE}1)${NC}  🚀 Установить"
        echo -e "   ${WHITE}2)${NC}  ▶️  Запустить"
        echo -e "   ${WHITE}3)${NC}  ⏹️  Остановить"
        echo -e "   ${WHITE}4)${NC}  🔄 Перезапустить"
        echo -e "   ${WHITE}5)${NC}  📊 Статус"
        echo
        echo -e "${WHITE}📋 Управление:${NC}"
        echo -e "   ${WHITE}6)${NC}  🔗 Ссылки для подключения"
        echo -e "   ${WHITE}7)${NC}  🎨 Шаблоны сайта"
        echo -e "   ${WHITE}8)${NC}  📝 Логи"
        echo -e "   ${WHITE}9)${NC}  🏷️  Обновить TAG"
        echo -e "   ${WHITE}10)${NC} ✏️  Редактировать конфиг"
        echo
        echo -e "${WHITE}🗑️  Обслуживание:${NC}"
        echo -e "   ${WHITE}11)${NC} 🗑️  Удалить всё"
        echo
        echo -e "   ${GRAY}0)${NC}  ⬅️  Выход"
        echo

        read -p "$(echo -e "${WHITE}Выберите [0-11]:${NC} ")" choice

        case "$choice" in
            1)  install_command; read -p "Нажмите Enter..." ;;
            2)  up_command; read -p "Нажмите Enter..." ;;
            3)  down_command; read -p "Нажмите Enter..." ;;
            4)  restart_command; read -p "Нажмите Enter..." ;;
            5)  status_command; read -p "Нажмите Enter..." ;;
            6)  links_command; read -p "Нажмите Enter..." ;;
            7)  template_command ;;
            8)  logs_command; read -p "Нажмите Enter..." ;;
            9)  update_tag_command; read -p "Нажмите Enter..." ;;
            10) edit_command; read -p "Нажмите Enter..." ;;
            11) uninstall_command; read -p "Нажмите Enter..." ;;
            0)  clear; exit 0 ;;
            *)  log_error "Неверный выбор"; sleep 1 ;;
        esac
    done
}

# ============================================
# MAIN ENTRY POINT
# ============================================
COMMAND="${1:-}"

case "$COMMAND" in
    install)    install_command ;;
    up|start)   up_command ;;
    down|stop)  down_command ;;
    restart)    restart_command ;;
    status)     status_command ;;
    logs)       logs_command ;;
    links)      links_command ;;
    template)   template_command ;;
    update-tag) update_tag_command ;;
    edit)       edit_command ;;
    uninstall)  uninstall_command ;;
    help|-h|--help) show_help ;;
    menu)       main_menu ;;
    "")         main_menu ;;
    *)
        log_error "Неизвестная команда: $COMMAND"
        echo "Используйте: $APP_NAME help"
        exit 1
        ;;
esac
