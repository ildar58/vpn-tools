#!/usr/bin/env bash
#
# xray-block-analyzer.sh
#
# Диагностика уровня блокировки TCP-подключения к xray-ноде.
# Запускается СО СТОРОНЫ КЛИЕНТА (например, из РФ) и определяет,
# на каком уровне рвётся соединение до ноды:
#
#   - DNS      (подмена / блокировка ответа резолвера)
#   - L3 / IP  (нуль-роут, блэкхол, потеря пакетов по пути)
#   - L4 / TCP (пассивный дроп SYN на IP:порт, или инъекция RST от DPI)
#   - L7 / TLS (блокировка по SNI, реакция DPI на ClientHello)
#
# Поддерживается адрес ноды в виде домена (приоритетно), а также ip:порт.
#
# Для максимальной диагностики (TTL-анализ RST-инъекций) нужен root
# и tcpdump/traceroute — скрипт предложит доустановить недостающее.
#
# Использование:
#   sudo bash xray-block-analyzer.sh <домен|ip>[:порт] [порт] [опции]
#
# Опции:
#   --sni <name>       SNI для TLS-теста (по умолчанию = домен ноды)
#   --control <host>   контрольный хост для базовой проверки инета
#                      (по умолчанию www.google.com:443)
#   --no-install       не пытаться доустанавливать инструменты
#   --attempts N       число попыток TCP-проб (по умолчанию 4)
#   -h, --help         показать справку
#
# Примеры:
#   sudo bash xray-block-analyzer.sh node.example.com
#   sudo bash xray-block-analyzer.sh node.example.com:2053
#   sudo bash xray-block-analyzer.sh 203.0.113.10 443 --sni www.microsoft.com
#
set -uo pipefail

# ---------------------------------------------------------------------------
# Логирование
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'; C_OK=$'\033[32m'; C_INFO=$'\033[36m'
  C_WARN=$'\033[33m'; C_ERR=$'\033[31m'; C_HEAD=$'\033[1;35m'; C_DIM=$'\033[2m'
else
  C_RESET=""; C_OK=""; C_INFO=""; C_WARN=""; C_ERR=""; C_HEAD=""; C_DIM=""
fi

log_ok()   { echo "${C_OK}[+]${C_RESET} $*"; }
log_info() { echo "${C_INFO}[=]${C_RESET} $*"; }
log_warn() { echo "${C_WARN}[!]${C_RESET} $*"; }
log_err()  { echo "${C_ERR}[x]${C_RESET} $*"; }
log_dim()  { echo "${C_DIM}    $*${C_RESET}"; }
section()  { echo; echo "${C_HEAD}=== $* ===${C_RESET}"; }

# ---------------------------------------------------------------------------
# Разбор аргументов
# ---------------------------------------------------------------------------
usage() {
  sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

TARGET_ARG=""
PORT=""
SNI=""
CONTROL="www.google.com:443"
DO_INSTALL=1
ATTEMPTS=4

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)    usage 0 ;;
    --sni)        SNI="${2:-}"; shift 2 ;;
    --control)    CONTROL="${2:-}"; shift 2 ;;
    --no-install) DO_INSTALL=0; shift ;;
    --attempts)   ATTEMPTS="${2:-4}"; shift 2 ;;
    -*)           log_err "Неизвестная опция: $1"; usage 1 ;;
    *)
      if [[ -z "$TARGET_ARG" ]]; then TARGET_ARG="$1"
      elif [[ -z "$PORT" ]]; then PORT="$1"
      else log_err "Лишний аргумент: $1"; usage 1
      fi
      shift ;;
  esac
done

if [[ -z "$TARGET_ARG" ]]; then
  log_err "Не указан адрес ноды (домен или ip)."
  usage 1
fi

# Разбор форм: host:port, [ipv6]:port, host + отдельный порт
HOST=""
if [[ "$TARGET_ARG" == \[*\]:* ]]; then          # [ipv6]:port
  HOST="${TARGET_ARG%]:*}"; HOST="${HOST#[}"
  PORT="${PORT:-${TARGET_ARG##*]:}}"
elif [[ "$TARGET_ARG" == *:*:* ]]; then          # голый ipv6 без порта
  HOST="$TARGET_ARG"
elif [[ "$TARGET_ARG" == *:* ]]; then            # host:port
  HOST="${TARGET_ARG%:*}"
  PORT="${PORT:-${TARGET_ARG##*:}}"
else
  HOST="$TARGET_ARG"
fi
PORT="${PORT:-443}"

if ! [[ "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
  log_err "Некорректный порт: $PORT"
  exit 1
fi

# Является ли HOST литеральным IP?
is_ip() { [[ "$1" =~ ^[0-9]+(\.[0-9]+){3}$ ]] || [[ "$1" == *:*:* ]]; }

IS_DOMAIN=1
is_ip "$HOST" && IS_DOMAIN=0

# SNI по умолчанию = домен (для IP оставляем пустым до появления явного --sni)
if [[ -z "$SNI" && "$IS_DOMAIN" -eq 1 ]]; then SNI="$HOST"; fi

CONTROL_HOST="${CONTROL%:*}"
CONTROL_PORT="${CONTROL##*:}"
[[ "$CONTROL_PORT" == "$CONTROL_HOST" ]] && CONTROL_PORT=443

IS_ROOT=0
[[ "${EUID:-$(id -u)}" -eq 0 ]] && IS_ROOT=1

# ---------------------------------------------------------------------------
# Флаги-выводы для итогового вердикта
# ---------------------------------------------------------------------------
V_DNS="skip"          # ok | spoof | blocked | skip
V_ICMP="skip"         # ok | fail | skip
V_TCP="skip"          # ok | timeout | reset | skip
V_TCP_ALT="skip"      # ok | none  (другие порты того же IP)
V_RST_INJECT="skip"   # yes | no | skip
V_TLS="skip"          # ok | reset | timeout | skip | n/a
V_TLS_BENIGN="skip"   # ok | reset | n/a
V_CONTROL="skip"      # ok | fail
LAST_HOP=""           # последний достижимый хоп traceroute
REF_TTL=""            # эталонный TTL «живого» пакета от сервера

# ---------------------------------------------------------------------------
# Определение и доустановка инструментов
# ---------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

PKG_MGR=""
detect_pkg_mgr() {
  if   have apt-get; then PKG_MGR="apt"
  elif have dnf;     then PKG_MGR="dnf"
  elif have yum;     then PKG_MGR="yum"
  elif have pacman;  then PKG_MGR="pacman"
  elif have brew;    then PKG_MGR="brew"
  fi
}

# карта: команда -> пакет (для apt/deb в первую очередь)
pkg_for() {
  case "$1" in
    dig)        echo "dnsutils" ;;
    traceroute) echo "traceroute" ;;
    tcpdump)    echo "tcpdump" ;;
    hping3)     echo "hping3" ;;
    mtr)        echo "mtr-tiny" ;;
    openssl)    echo "openssl" ;;
    nc|ncat)    echo "ncat" ;;
    *)          echo "$1" ;;
  esac
}

install_pkg() {
  local pkg="$1"
  case "$PKG_MGR" in
    apt)    DEBIAN_FRONTEND=noninteractive apt-get install -yqq "$pkg" >/dev/null 2>&1 ;;
    dnf)    dnf install -y "$pkg" >/dev/null 2>&1 ;;
    yum)    yum install -y "$pkg" >/dev/null 2>&1 ;;
    pacman) pacman -Sy --noconfirm "$pkg" >/dev/null 2>&1 ;;
    brew)   brew install "$pkg" >/dev/null 2>&1 ;;
    *)      return 1 ;;
  esac
}

ensure_tool() {
  # ensure_tool <cmd> <critical:0|1>
  local cmd="$1" critical="${2:-0}"
  have "$cmd" && return 0

  if [[ "$DO_INSTALL" -eq 1 && "$IS_ROOT" -eq 1 && -n "$PKG_MGR" ]]; then
    local pkg; pkg="$(pkg_for "$cmd")"
    log_info "Доустанавливаю '$cmd' (пакет $pkg)..."
    if install_pkg "$pkg" && have "$cmd"; then
      log_ok "Установлен: $cmd"
      return 0
    fi
  fi

  if [[ "$critical" -eq 1 ]]; then
    log_err "Отсутствует обязательный инструмент: $cmd"
    return 1
  fi
  log_warn "Инструмент '$cmd' недоступен — соответствующие проверки будут пропущены."
  return 1
}

detect_pkg_mgr

section "Параметры диагностики"
log_info "Нода:        $HOST : $PORT $([[ $IS_DOMAIN -eq 1 ]] && echo '(домен)' || echo '(IP)')"
log_info "SNI для TLS: ${SNI:-<не задан>}"
log_info "Контроль:    $CONTROL_HOST : $CONTROL_PORT"
log_info "Root:        $([[ $IS_ROOT -eq 1 ]] && echo да || echo 'нет — TTL-анализ RST будет пропущен')"
log_info "Менеджер пакетов: ${PKG_MGR:-не найден}"

if [[ "$IS_ROOT" -ne 1 ]]; then
  log_warn "Скрипт запущен НЕ от root. Для полного анализа (инъекция RST по TTL)"
  log_warn "перезапустите через sudo. Базовые проверки всё равно будут выполнены."
fi

ensure_tool openssl 1 || { log_err "Без openssl продолжать нельзя."; exit 1; }
ensure_tool curl 0       >/dev/null 2>&1 || true   # для DoH-сверки DNS
ensure_tool dig 0        && HAVE_DIG=1        || HAVE_DIG=0
ensure_tool traceroute 0 && HAVE_TRACEROUTE=1 || HAVE_TRACEROUTE=0
ensure_tool tcpdump 0    && HAVE_TCPDUMP=1    || HAVE_TCPDUMP=0

# ---------------------------------------------------------------------------
# 1. DNS
# ---------------------------------------------------------------------------
declare -a TARGET_IPS=()

resolve_system() {
  # Разрешение штатным резолвером ОС
  local h="$1"
  if have getent; then
    getent ahostsv4 "$h" 2>/dev/null | awk '{print $1}' | sort -u
  elif have python3; then
    python3 - "$h" <<'PY' 2>/dev/null
import socket,sys
try:
    for _,_,_,_,sa in socket.getaddrinfo(sys.argv[1],None,socket.AF_INET):
        print(sa[0])
except Exception:
    pass
PY
  fi
}

dig_at() {
  # dig_at <resolver> <host>  — plaintext DNS (UDP/53) через конкретный резолвер
  [[ "$HAVE_DIG" -eq 1 ]] || return 1
  dig +short +time=3 +tries=1 A "$2" "@$1" 2>/dev/null \
    | grep -E '^[0-9]+(\.[0-9]+){3}$' | sort -u
}

doh_lookup() {
  # doh_lookup <host> — «эталон» через DoH (DNS-over-HTTPS).
  # DPI не может подменить зашифрованный ответ, поэтому это опорная истина.
  local h="$1" out
  have curl || return 1
  # Cloudflare DoH (JSON). При недоступности — Google DoH.
  out="$(curl -fsS --max-time 8 -H 'accept: application/dns-json' \
         "https://1.1.1.1/dns-query?name=${h}&type=A" 2>/dev/null)"
  [[ -z "$out" ]] && out="$(curl -fsS --max-time 8 \
         "https://dns.google/resolve?name=${h}&type=A" 2>/dev/null)"
  [[ -z "$out" ]] && return 1
  # Вытаскиваем "data":"1.2.3.4" из JSON без jq
  echo "$out" | grep -oE '"data":"[0-9]+(\.[0-9]+){3}"' \
    | grep -oE '[0-9]+(\.[0-9]+){3}' | sort -u
}

# Приватные/blackhole/«заглушечные» адреса, которыми часто подменяют DNS
is_bogus_ip() {
  echo "$1" | grep -qE '^(0\.0\.0\.0|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|100\.6[4-9]\.|100\.[7-9][0-9]\.|100\.1[01][0-9]\.|100\.12[0-7]\.)'
}

section "1. DNS-резолвинг"
if [[ "$IS_DOMAIN" -eq 0 ]]; then
  log_info "Адрес задан как IP — DNS-проверка не требуется."
  TARGET_IPS=("$HOST")
  V_DNS="skip"
else
  sys_ips="$(resolve_system "$HOST")"
  if [[ -n "$sys_ips" ]]; then
    log_ok "Системный резолвер:   $(echo "$sys_ips" | tr '\n' ' ')"
  else
    log_err "Системный резолвер НЕ разрешил домен (ответ отсутствует / NXDOMAIN)."
  fi

  g_ips=""; c_ips=""
  if [[ "$HAVE_DIG" -eq 1 ]]; then
    g_ips="$(dig_at 8.8.8.8 "$HOST")"
    c_ips="$(dig_at 1.1.1.1 "$HOST")"
    [[ -n "$g_ips" ]] && log_info "UDP/53 @8.8.8.8:      $(echo "$g_ips" | tr '\n' ' ')" \
                      || log_warn "UDP/53 @8.8.8.8: ответа нет (перехват/дроп UDP/53)"
    [[ -n "$c_ips" ]] && log_info "UDP/53 @1.1.1.1:      $(echo "$c_ips" | tr '\n' ' ')" \
                      || log_warn "UDP/53 @1.1.1.1: ответа нет (перехват/дроп UDP/53)"
  fi

  # DoH — опорный «незасоряемый» ответ
  doh_ips="$(doh_lookup "$HOST")"
  if [[ -n "$doh_ips" ]]; then
    log_ok "DoH (эталон):         $(echo "$doh_ips" | tr '\n' ' ')"
  else
    log_warn "DoH-ответ получить не удалось (нет curl или HTTPS к DoH тоже режется)."
  fi

  # Для дальнейших тестов берём максимально «правдивый» набор IP:
  # DoH -> внешние UDP -> системный.
  chosen=""
  if   [[ -n "$doh_ips" ]]; then chosen="$doh_ips"
  elif [[ -n "$g_ips"   ]]; then chosen="$g_ips"
  elif [[ -n "$c_ips"   ]]; then chosen="$c_ips"
  else                           chosen="$sys_ips"
  fi
  while read -r ip; do [[ -n "$ip" ]] && TARGET_IPS+=("$ip"); done <<< "$chosen"

  # -------- Анализ признаков DNS-блокировки --------
  # bogus в любом plaintext-ответе
  bogus_sys="no"; bogus_ext="no"
  while read -r ip; do [[ -n "$ip" ]] && is_bogus_ip "$ip" && bogus_sys="yes"; done <<< "$sys_ips"
  while read -r ip; do [[ -n "$ip" ]] && is_bogus_ip "$ip" && bogus_ext="yes"; done <<< "$(printf '%s\n%s\n' "$g_ips" "$c_ips")"

  # пересечение plaintext с эталоном DoH
  overlap_sys_doh="na"; overlap_ext_doh="na"
  ext_ips="$(printf '%s\n%s\n' "$g_ips" "$c_ips" | grep -E '^[0-9]' | sort -u)"
  if [[ -n "$doh_ips" ]]; then
    [[ -n "$sys_ips" ]] && overlap_sys_doh="$(comm -12 <(echo "$sys_ips" | sort -u) <(echo "$doh_ips") 2>/dev/null)"
    [[ -n "$ext_ips" ]] && overlap_ext_doh="$(comm -12 <(echo "$ext_ips") <(echo "$doh_ips") 2>/dev/null)"
  fi

  if [[ "$bogus_sys" == "yes" ]]; then
    log_err "Системный резолвер вернул приватный/заглушечный IP → ПОДМЕНА DNS (fake answer)."
    V_DNS="spoof"
  elif [[ "$bogus_ext" == "yes" ]]; then
    log_err "Даже внешний резолвер (8.8.8.8/1.1.1.1) вернул фейковый IP → ПРОЗРАЧНЫЙ ПЕРЕХВАТ UDP/53."
    log_dim "Провайдер заворачивает весь plaintext-DNS на свой резолвер и подменяет ответ."
    V_DNS="spoof"
  elif [[ -n "$doh_ips" && -z "$sys_ips" && -z "$g_ips" && -z "$c_ips" ]]; then
    log_err "Plaintext-DNS не отвечает ни через кого, а DoH домен резолвит → DNS-ответы РЕЖУТСЯ."
    log_dim "Классическая DNS-блокировка: ответ по UDP/53 дропается, IP достаётся только по DoH."
    V_DNS="blocked"
  elif [[ -n "$doh_ips" && "$overlap_sys_doh" != "na" && -z "$overlap_sys_doh" ]]; then
    log_warn "Ответ системного резолвера НЕ совпадает с эталоном DoH → вероятна подмена DNS."
    log_dim "(либо CDN/geo-DNS — сверьте адреса; но при блокировке это типичная картина)."
    V_DNS="spoof"
  elif [[ -n "$doh_ips" && "$overlap_ext_doh" != "na" && -z "$overlap_ext_doh" && -n "$ext_ips" ]]; then
    log_warn "Ответ внешних UDP-резолверов расходится с DoH → инъекция DNS-ответов на пути."
    V_DNS="spoof"
  elif [[ -z "$sys_ips" && ( -n "$g_ips" || -n "$c_ips" || -n "$doh_ips" ) ]]; then
    log_warn "Системный резолвер молчит, но домен резолвится извне → блокировка/сбой резолвера ISP."
    V_DNS="spoof"
  elif [[ ${#TARGET_IPS[@]} -gt 0 ]]; then
    log_ok "Явных признаков подмены DNS не обнаружено."
    V_DNS="ok"
  else
    log_err "Домен не резолвится ни одним способом."
    V_DNS="blocked"
  fi
fi

if [[ ${#TARGET_IPS[@]} -eq 0 ]]; then
  log_err "Не удалось получить ни одного IP ноды. Дальнейшие сетевые тесты невозможны."
  V_DNS="blocked"
  IP=""
else
  IP="${TARGET_IPS[0]}"
  log_ok "Целевой IP для тестов: $IP"
fi

# ---------------------------------------------------------------------------
# 2. L3 / IP — ICMP и маршрут
# ---------------------------------------------------------------------------
section "2. Сетевой уровень (L3 / IP)"
if [[ -n "$IP" ]]; then
  if ping -c 3 -W 2 "$IP" >/tmp/xba_ping.$$ 2>&1; then
    rtt="$(grep -oE 'time=[0-9.]+' /tmp/xba_ping.$$ | head -1)"
    t_ttl="$(grep -oE 'ttl=[0-9]+' /tmp/xba_ping.$$ | head -1 | cut -d= -f2)"
    log_ok "ICMP ping проходит ($rtt${t_ttl:+, TTL=$t_ttl})"
    V_ICMP="ok"
    [[ -n "$t_ttl" ]] && REF_TTL="$t_ttl"
  else
    log_warn "ICMP ping НЕ проходит (часто нормально — ICMP режут и штатно)."
    V_ICMP="fail"
  fi
  rm -f /tmp/xba_ping.$$

  if [[ "$HAVE_TRACEROUTE" -eq 1 ]]; then
    log_info "Трассировка маршрута до $IP:$PORT (TCP SYN)..."
    tr_out=""
    if [[ "$IS_ROOT" -eq 1 ]]; then
      tr_out="$(traceroute -n -T -p "$PORT" -w 2 -q 1 -m 20 "$IP" 2>/dev/null)"
    fi
    # если TCP-трасса пустая/недоступна — обычный ICMP/UDP traceroute
    if [[ -z "$tr_out" || "$(echo "$tr_out" | wc -l)" -lt 2 ]]; then
      tr_out="$(traceroute -n -w 2 -q 1 -m 20 "$IP" 2>/dev/null)"
    fi
    if [[ -n "$tr_out" ]]; then
      echo "$tr_out" | sed 's/^/    /'
      # последний хоп, который ответил (не '* * *')
      LAST_HOP="$(echo "$tr_out" | awk 'NF>1 && $2!="*" {hop=$0} END{print hop}')"
      reached="$(echo "$tr_out" | grep -E "(^|[^0-9])$(echo "$IP" | sed 's/\./\\./g')([^0-9]|$)")"
      if [[ -n "$reached" ]]; then
        log_ok "Трассировка ДОШЛА до целевого IP."
      else
        log_warn "Трассировка НЕ дошла до целевого IP — пакеты гибнут по пути."
        log_dim "Последний ответивший хоп: $(echo "$LAST_HOP" | awk '{print $2}')"
      fi
    else
      log_warn "traceroute не дал вывода."
    fi
  fi
else
  V_ICMP="skip"
fi

# ---------------------------------------------------------------------------
# Вспомогательное: одиночная TCP-проба через /dev/tcp
#   печатает: connected | timeout | reset  (+ код возврата)
# ---------------------------------------------------------------------------
tcp_probe() {
  local ip="$1" port="$2" to="${3:-5}" rc
  timeout "$to" bash -c "exec 3<>/dev/tcp/$ip/$port" >/dev/null 2>&1
  rc=$?
  if   [[ $rc -eq 0 ]];   then echo "connected"
  elif [[ $rc -eq 124 ]]; then echo "timeout"
  else                         echo "reset"   # ECONNREFUSED / RST / unreachable
  fi
}

# ---------------------------------------------------------------------------
# 3. L4 / TCP — установка соединения
# ---------------------------------------------------------------------------
section "3. Транспортный уровень (L4 / TCP)"
declare -A tcp_hist=([connected]=0 [timeout]=0 [reset]=0)
if [[ -n "$IP" ]]; then
  log_info "TCP-пробы на $IP:$PORT (попыток: $ATTEMPTS)..."
  for i in $(seq 1 "$ATTEMPTS"); do
    r="$(tcp_probe "$IP" "$PORT" 5)"
    tcp_hist[$r]=$(( ${tcp_hist[$r]} + 1 ))
    log_dim "попытка $i: $r"
  done
  # Доминирующий исход
  best="connected"; bestn=-1
  for k in connected timeout reset; do
    (( ${tcp_hist[$k]} > bestn )) && { best="$k"; bestn=${tcp_hist[$k]}; }
  done
  case "$best" in
    connected) log_ok  "TCP-хендшейк УСПЕШЕН (${tcp_hist[connected]}/$ATTEMPTS). L4 до IP:порт открыт."; V_TCP="ok" ;;
    timeout)   log_err "TCP-хендшейк: ТАЙМАУТ (${tcp_hist[timeout]}/$ATTEMPTS). SYN уходит без ответа — пассивный дроп."; V_TCP="timeout" ;;
    reset)     log_err "TCP-хендшейк: RST/REFUSED (${tcp_hist[reset]}/$ATTEMPTS). Активный сброс соединения."; V_TCP="reset" ;;
  esac
  log_dim "итог: connected=${tcp_hist[connected]} timeout=${tcp_hist[timeout]} reset=${tcp_hist[reset]}"

  # Сравнение с другими портами того же IP — порт-специфична ли блокировка
  if [[ "$V_TCP" != "ok" ]]; then
    log_info "Сравниваю с другими портами того же IP..."
    V_TCP_ALT="none"
    for altp in 443 80 22; do
      [[ "$altp" == "$PORT" ]] && continue
      ar="$(tcp_probe "$IP" "$altp" 4)"
      log_dim "порт $altp: $ar"
      [[ "$ar" == "connected" ]] && V_TCP_ALT="ok"
    done
    if [[ "$V_TCP_ALT" == "ok" ]]; then
      log_warn "Другой порт того же IP отвечает → блокировка ПОРТ-специфична (фильтр по IP:порт)."
    else
      log_warn "Все проверенные порты недоступны → блокировка на уровне всего IP (или хост лежит)."
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 4. TTL-анализ инъекции RST (root + tcpdump)
# ---------------------------------------------------------------------------
section "4. Детект инъекции RST от DPI (TTL-анализ)"
if [[ "$IS_ROOT" -eq 1 && "$HAVE_TCPDUMP" -eq 1 && -n "$IP" ]]; then
  cap="/tmp/xba_cap.$$"
  # Слушаем SYN-ACK и RST от сервера в отдельном процессе
  tcpdump -n -i any -c 40 -v "host $IP and tcp port $PORT and (tcp[tcpflags] & (tcp-rst) != 0 or tcp[tcpflags] & (tcp-syn) != 0)" \
      >"$cap" 2>/dev/null &
  tdpid=$!
  sleep 0.5
  # Провоцируем соединение (несколько раз, чтобы поймать инъекцию)
  for i in 1 2 3; do tcp_probe "$IP" "$PORT" 4 >/dev/null; done
  sleep 1
  kill "$tdpid" >/dev/null 2>&1; wait "$tdpid" 2>/dev/null

  synack_ttls="$(grep -E 'Flags \[S\.\]' "$cap" | grep -oE 'ttl [0-9]+' | awk '{print $2}' | sort -un)"
  rst_ttls="$(grep -E 'Flags \[R' "$cap" | grep -oE 'ttl [0-9]+' | awk '{print $2}' | sort -un)"
  rst_count="$(grep -cE 'Flags \[R' "$cap")"

  [[ -n "$synack_ttls" ]] && log_info "TTL пакетов SYN-ACK от сервера: $(echo "$synack_ttls" | tr '\n' ' ')"
  [[ -n "$rst_ttls" ]]    && log_info "TTL пакетов RST:               $(echo "$rst_ttls" | tr '\n' ' ')  (всего RST: $rst_count)"

  # эталонный TTL живого пакета сервера
  [[ -n "$synack_ttls" ]] && REF_TTL="$(echo "$synack_ttls" | tail -1)"

  if [[ -z "$rst_ttls" ]]; then
    log_info "RST-пакеты не пойманы."
    V_RST_INJECT="no"
  else
    inject="no"
    # 1) есть и SYN-ACK, и RST с ОТЛИЧНЫМ TTL → инъекция «поверх» живого соединения
    if [[ -n "$synack_ttls" ]]; then
      for rt in $rst_ttls; do
        match="no"
        for st in $synack_ttls; do
          d=$(( rt > st ? rt - st : st - rt ))
          (( d <= 2 )) && match="yes"
        done
        [[ "$match" == "no" ]] && inject="yes"
      done
    fi
    # 2) несколько RST с разными TTL → часть подделана
    if [[ "$(echo "$rst_ttls" | wc -l)" -gt 1 ]]; then inject="yes"; fi
    # 3) RST при пойманном SYN-ACK — сервер согласился, но соединение сброшено
    if [[ -n "$synack_ttls" && "$rst_count" -gt 0 ]]; then
      log_warn "Сервер ответил SYN-ACK, но соединение было СБРОШЕНО RST-ом."
    fi

    if [[ "$inject" == "yes" ]]; then
      log_err "TTL RST не совпадает с TTL живых пакетов сервера → RST ПОДДЕЛАН (инъекция DPI)."
      V_RST_INJECT="yes"
    else
      log_info "TTL RST согласуется с сервером → похоже на легитимный сброс (порт закрыт/сервер режет)."
      V_RST_INJECT="no"
    fi
  fi
  rm -f "$cap"
else
  log_warn "Пропуск: нужен root + tcpdump (TTL-анализ RST-инъекций недоступен)."
  V_RST_INJECT="skip"
fi

# ---------------------------------------------------------------------------
# 5. L7 / TLS — реакция на ClientHello и SNI
# ---------------------------------------------------------------------------
tls_probe() {
  # tls_probe <ip> <port> <sni>  -> ok | reset | timeout
  local ip="$1" port="$2" sni="$3" out rc
  local args=(-connect "$ip:$port" -tls1_2 -crlf -verify_quiet -brief)
  [[ -n "$sni" ]] && args+=(-servername "$sni")
  out="$(echo -e 'GET / HTTP/1.0\r\n\r\n' | timeout 10 openssl s_client "${args[@]}" 2>&1)"
  rc=$?
  if echo "$out" | grep -qiE 'Protocol|Cipher|Verification|CONNECTED.*Server certificate|Server public key|Post-Handshake'; then
    echo "ok"
  elif [[ $rc -eq 124 ]]; then
    echo "timeout"
  elif echo "$out" | grep -qiE 'reset by peer|BROKEN PIPE|no peer certificate|handshake failure|tlsv1|ssl handshake'; then
    echo "reset"
  elif echo "$out" | grep -qiE 'connect:errno|Connection refused|No route'; then
    echo "reset"
  else
    echo "reset"
  fi
}

section "5. Прикладной уровень (L7 / TLS, SNI)"
if [[ "$V_TCP" == "ok" && -n "$IP" ]]; then
  # с целевым SNI
  if [[ -n "$SNI" ]]; then
    log_info "TLS-хендшейк с целевым SNI: $SNI"
    r="$(tls_probe "$IP" "$PORT" "$SNI")"
    case "$r" in
      ok)      log_ok  "TLS с SNI '$SNI' завершился успешно."; V_TLS="ok" ;;
      timeout) log_err "TLS с SNI '$SNI': таймаут (ClientHello уходит без ответа)."; V_TLS="timeout" ;;
      reset)   log_err "TLS с SNI '$SNI': соединение сброшено во время хендшейка."; V_TLS="reset" ;;
    esac
  else
    log_info "SNI не задан (нода по IP) — тест TLS без SNI."
    r="$(tls_probe "$IP" "$PORT" "")"
    [[ "$r" == "ok" ]] && { log_ok "TLS без SNI успешен."; V_TLS="ok"; } \
                       || { log_warn "TLS без SNI: $r"; V_TLS="$r"; }
  fi

  # контрольный «безобидный» SNI на том же IP:порт — вычленяем блокировку по SNI
  if [[ "$V_TLS" != "ok" ]]; then
    benign="www.microsoft.com"
    log_info "Контроль: тот же IP:порт с безобидным SNI '$benign'..."
    rb="$(tls_probe "$IP" "$PORT" "$benign")"
    log_dim "результат с '$benign': $rb"
    V_TLS_BENIGN="$rb"
    if [[ "$rb" == "ok" && ( "$V_TLS" == "reset" || "$V_TLS" == "timeout" ) ]]; then
      log_err "С безобидным SNI TLS проходит, а с целевым — рвётся → БЛОКИРОВКА ПО SNI (DPI на ClientHello)."
    elif [[ "$rb" != "ok" ]]; then
      log_warn "Безобидный SNI тоже не проходит → сброс не привязан к конкретному SNI"
      log_dim "(общий DPI на TLS/протокол, либо особенность самой ноды)."
    fi
  fi
else
  log_info "TCP-соединение не установлено — TLS-тест пропущен (блок ниже L7)."
  V_TLS="n/a"
fi

# ---------------------------------------------------------------------------
# 6. Контрольная проверка «а работает ли интернет вообще»
# ---------------------------------------------------------------------------
section "6. Контроль: базовая работоспособность канала"
c_ip="$CONTROL_HOST"
if ! is_ip "$CONTROL_HOST"; then
  c_ip="$(resolve_system "$CONTROL_HOST" | head -1)"
fi
if [[ -n "$c_ip" ]]; then
  ctcp="$(tcp_probe "$c_ip" "$CONTROL_PORT" 5)"
  if [[ "$ctcp" == "connected" ]]; then
    ctls="$(tls_probe "$c_ip" "$CONTROL_PORT" "$CONTROL_HOST")"
    if [[ "$ctls" == "ok" ]]; then
      log_ok "Контрольный $CONTROL_HOST:$CONTROL_PORT — TCP+TLS работают. Канал в целом исправен."
      V_CONTROL="ok"
    else
      log_warn "Контрольный TCP ок, но TLS = $ctls. Возможен общий DPI на TLS."
      V_CONTROL="ok"
    fi
  else
    log_err "Контрольный $CONTROL_HOST:$CONTROL_PORT недоступен ($ctcp) — проблема, похоже, В САМОМ КАНАЛЕ, не в ноде."
    V_CONTROL="fail"
  fi
else
  log_warn "Не удалось разрешить контрольный хост $CONTROL_HOST."
fi

# ---------------------------------------------------------------------------
# 7. Итоговый вердикт
# ---------------------------------------------------------------------------
section "ИТОГОВЫЙ ВЕРДИКТ"

# Выравнивание с учётом кириллицы: ${#label} считает символы, а не байты.
row() {
  local label="$1" val="$2" width=26 len pad
  len=${#label}; pad=$(( width - len )); (( pad < 1 )) && pad=1
  printf "    %s%*s%s\n" "$label" "$pad" "" "$val"
}

echo "  Сводка проверок:"
row "DNS-резолвинг:"      "$V_DNS"
row "ICMP (L3):"          "$V_ICMP"
row "TCP-хендшейк (L4):"  "$V_TCP"
[[ "$V_TCP" != "ok" ]] && row "др. порты того же IP:" "$V_TCP_ALT"
row "Инъекция RST (DPI):" "$V_RST_INJECT"
row "TLS/SNI (L7):"       "$V_TLS"
[[ "$V_TLS_BENIGN" != "skip" ]] && row "TLS с др. SNI:" "$V_TLS_BENIGN"
row "Контрольный канал:"  "$V_CONTROL"
echo

verdict() { echo "  ${C_HEAD}➤ $*${C_RESET}"; }

decided=0

if [[ "$V_CONTROL" == "fail" ]]; then
  verdict "УРОВЕНЬ: канал/провайдер целиком."
  log_dim "Даже контрольный публичный хост недоступен. Дело не в конкретной ноде —"
  log_dim "проверьте интернет, роутер, общий шатдаун/фильтрацию у провайдера."
  decided=1
fi

if [[ "$decided" -eq 0 && ( "$V_DNS" == "spoof" || "$V_DNS" == "blocked" ) ]]; then
  verdict "УРОВЕНЬ: DNS."
  if [[ "$V_DNS" == "spoof" ]]; then
    log_dim "Резолвер отдаёт ПОДМЕНЁННЫЙ адрес (fake answer / прозрачный перехват UDP/53)."
  else
    log_dim "Ответ по UDP/53 РЕЖЕТСЯ — домен не резолвится обычным DNS."
  fi
  if [[ -n "${doh_ips:-}" ]]; then
    log_dim "При этом DoH домен резолвит корректно → это ТОЧНО DNS-уровень, а не L3/L4."
    log_dim "Настоящий IP ноды (по DoH): $(echo "$doh_ips" | tr '\n' ' ')"
    if [[ "$V_TCP" == "ok" ]]; then
      log_dim "TCP к этому IP проходит — достаточно починить DNS, и нода заработает."
    fi
  fi
  log_dim "Обход: включить DoH/DoT в клиенте/системе (Cloudflare 1.1.1.1, Google),"
  log_dim "прописать resolver вручную, или указать IP ноды в клиенте напрямую (минуя DNS)."
  decided=1
fi

if [[ "$decided" -eq 0 && "$V_TCP" == "timeout" ]]; then
  if [[ "$V_TCP_ALT" == "ok" ]]; then
    verdict "УРОВЕНЬ: L4, фильтр по IP:порт (пассивный дроп SYN)."
    log_dim "SYN на целевой порт молча теряется, но другой порт того же IP отвечает."
    log_dim "Обход: сменить порт ноды (напр. 443), домен-фронтинг, другой транспорт."
  else
    verdict "УРОВЕНЬ: L3/L4, блокировка всего IP (блэкхол/нуль-роут)."
    log_dim "Ни один порт IP не отвечает, SYN гибнет."
    [[ -n "$LAST_HOP" ]] && log_dim "Пакеты умирают после хопа: $(echo "$LAST_HOP" | awk '{print $2}')"
    log_dim "Обход: сменить IP ноды (пересоздать/мигрировать), CDN-прокси перед нодой."
  fi
  decided=1
fi

if [[ "$decided" -eq 0 && "$V_TCP" == "reset" ]]; then
  if [[ "$V_RST_INJECT" == "yes" ]]; then
    verdict "УРОВЕНЬ: L4, активная инъекция RST со стороны DPI."
    log_dim "TTL RST-пакетов не совпадает с TTL живого сервера — сброс подделан посредником."
    log_dim "Обход: обфускация (Reality/XTLS с корректным SNI), смена порта, TCP-фрагментация."
  else
    verdict "УРОВЕНЬ: сервис/файрвол ноды (легитимный RST)."
    log_dim "TCP сбрасывается, но TTL согласуется с сервером — вероятно, порт закрыт,"
    log_dim "xray не слушает этот порт, либо режет сам файрвол ноды (ufw/iptables)."
    log_dim "Проверьте на ноде: docker/xray запущен, порт слушается, ufw allow <порт>/tcp."
  fi
  decided=1
fi

if [[ "$decided" -eq 0 && "$V_TCP" == "ok" ]]; then
  if [[ "$V_TLS" == "reset" || "$V_TLS" == "timeout" ]]; then
    if [[ "$V_TLS_BENIGN" == "ok" ]]; then
      verdict "УРОВЕНЬ: L7, блокировка по SNI (DPI на ClientHello)."
      log_dim "TCP открыт, безобидный SNI проходит, а целевой SNI обрывается."
      log_dim "Обход: Reality/uTLS с SNI известного «белого» сайта, смена servername."
    else
      verdict "УРОВЕНЬ: L7, DPI на TLS-рукопожатии (не только SNI)."
      log_dim "TCP открыт, но TLS рвётся при любом SNI — сигнатурный DPI на паттерн хендшейка,"
      log_dim "либо нода отвечает некорректно. Обход: Reality/обфускация, проверка конфига ноды."
    fi
  elif [[ "$V_TLS" == "ok" ]]; then
    verdict "Блокировки на уровнях DNS/L3/L4/TLS НЕ обнаружено."
    log_dim "TCP и TLS до ноды проходят. Если клиент всё равно не подключается —"
    log_dim "ищите выше: конфиг клиента (uuid/пароль/flow), сам xray на ноде,"
    log_dim "либо блокировка по объёму/поведению трафика (throttling), а не по установке сессии."
  else
    verdict "TCP до ноды открыт; TLS-тест неинформативен (Reality может не отвечать openssl)."
    log_dim "Это нормально для Reality/XTLS. Ключевое: L4 проходит — базовой блокировки нет."
  fi
  decided=1
fi

if [[ "$decided" -eq 0 ]]; then
  verdict "Недостаточно данных для однозначного вывода — см. сводку выше."
fi

echo
log_info "Готово. Для полного анализа RST-инъекций запускайте от root с tcpdump."
