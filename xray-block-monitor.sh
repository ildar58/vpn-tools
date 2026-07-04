#!/usr/bin/env bash
#
# xray-block-monitor.sh
#
# Мониторинг АДАПТИВНОЙ блокировки xray-ноды во времени (поведение ТСПУ).
#
# ТСПУ часто блокирует не сразу: какое-то время флоу «наблюдается», затем
# IP:порт заносится в блок на фиксированные ~5-10 минут (penalty-таймер),
# после чего блок снимается — и цикл повторяется. Одиночная проверка этого
# не ловит. Этот скрипт непрерывно зондирует ноду и строит «осциллограмму»
# доступности, замеряя тайминги эпизодов:
#
#   - time-to-block   — сколько нода работает до первого блока
#   - длительность    — сколько длится блок (кучность у 5-10 мин = penalty-таймер)
#   - период          — ритм «работает N / блок M»
#   - тип блока        — таймаут (пассивный blackhole) vs RST (активный сброс)
#   - контроль         — параллельная проба публичного хоста (точечный блок или общий сбой)
#
# Совместимо с Linux и macOS (bash 3.2, BSD/LibreSSL).
#
# Использование:
#   bash xray-block-monitor.sh <домен|ip>[:порт] [порт] [опции]
#
# Опции:
#   --interval N     секунд между пробами (по умолчанию 5)
#   --duration N     сколько всего секунд мониторить (по умолчанию 3600; 0 = до Ctrl-C)
#   --tls            дополнительно проверять TLS-хендшейк (ловит блок по SNI/L7)
#   --control H[:P]  контрольный хост (по умолчанию www.google.com:443)
#   --log FILE       писать CSV-лог проб
#   -h, --help       справка
#
# Совет: чтобы поймать блок, ТРИГГЕРящийся объёмом трафика, запускайте монитор
# ОДНОВРЕМЕННО с реальным использованием ноды (стриминг/скачивание через туннель).
# Монитор зафиксирует, в какой момент и на сколько нода «гаснет».
#
# Примеры:
#   bash xray-block-monitor.sh node.example.com --tls
#   bash xray-block-monitor.sh 203.0.113.10 443 --interval 3 --duration 0 --log run.csv
#
set -uo pipefail

# ---------------------------------------------------------------------------
# Логирование / цвета
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
section()  { echo; echo "${C_HEAD}=== $* ===${C_RESET}"; }

usage() { sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

# ---------------------------------------------------------------------------
# Аргументы
# ---------------------------------------------------------------------------
TARGET_ARG=""; PORT=""; INTERVAL=5; DURATION=3600
DO_TLS=0; CONTROL="www.google.com:443"; LOGFILE=""; SNI=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)   usage 0 ;;
    --interval)  INTERVAL="${2:-5}"; shift 2 ;;
    --duration)  DURATION="${2:-3600}"; shift 2 ;;
    --tls)       DO_TLS=1; shift ;;
    --sni)       SNI="${2:-}"; shift 2 ;;
    --control)   CONTROL="${2:-}"; shift 2 ;;
    --log)       LOGFILE="${2:-}"; shift 2 ;;
    -*)          log_err "Неизвестная опция: $1"; usage 1 ;;
    *) if [[ -z "$TARGET_ARG" ]]; then TARGET_ARG="$1"
       elif [[ -z "$PORT" ]]; then PORT="$1"
       else log_err "Лишний аргумент: $1"; usage 1; fi; shift ;;
  esac
done
[[ -z "$TARGET_ARG" ]] && { log_err "Не указан адрес ноды."; usage 1; }

# host[:port]
HOST=""
if [[ "$TARGET_ARG" == \[*\]:* ]]; then
  HOST="${TARGET_ARG%]:*}"; HOST="${HOST#[}"; PORT="${PORT:-${TARGET_ARG##*]:}}"
elif [[ "$TARGET_ARG" == *:*:* ]]; then
  HOST="$TARGET_ARG"
elif [[ "$TARGET_ARG" == *:* ]]; then
  HOST="${TARGET_ARG%:*}"; PORT="${PORT:-${TARGET_ARG##*:}}"
else
  HOST="$TARGET_ARG"
fi
PORT="${PORT:-443}"
{ [[ "$INTERVAL" =~ ^[0-9]+$ ]] && (( INTERVAL >= 1 )); } || { log_err "Некорректный --interval"; exit 1; }
[[ "$DURATION" =~ ^[0-9]+$ ]] || { log_err "Некорректный --duration"; exit 1; }

is_ip() { [[ "$1" =~ ^[0-9]+(\.[0-9]+){3}$ ]] || [[ "$1" == *:*:* ]]; }
[[ -z "$SNI" ]] && ! is_ip "$HOST" && SNI="$HOST"
CONTROL_HOST="${CONTROL%:*}"; CONTROL_PORT="${CONTROL##*:}"
[[ "$CONTROL_PORT" == "$CONTROL_HOST" ]] && CONTROL_PORT=443

# ---------------------------------------------------------------------------
# Портативные примитивы (Linux + macOS/bash 3.2)
# ---------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }
OS="$(uname -s 2>/dev/null || echo Linux)"

TIMEOUT_CMD=""
if   have timeout;  then TIMEOUT_CMD="timeout"
elif have gtimeout; then TIMEOUT_CMD="gtimeout"; fi

with_timeout() {
  local t="$1"; shift
  if [[ -n "$TIMEOUT_CMD" ]]; then "$TIMEOUT_CMD" "$t" "$@"; return $?; fi
  "$@" & local pid=$!
  ( sleep "$t"; kill -9 "$pid" 2>/dev/null ) >/dev/null 2>&1 & local wpid=$!
  wait "$pid" 2>/dev/null; local rc=$?
  kill "$wpid" 2>/dev/null; wait "$wpid" 2>/dev/null
  return $rc
}

resolve_host() {
  local h="$1"
  if is_ip "$h"; then echo "$h"; return; fi
  if have getent; then
    getent ahostsv4 "$h" 2>/dev/null | awk '{print $1}' | grep -E '^[0-9]+(\.[0-9]+){3}$' | head -1
  elif have dscacheutil; then
    dscacheutil -q host -a name "$h" 2>/dev/null | awk '/^ip_address:/{print $2}' | head -1
  elif have dig; then
    dig +short A "$h" 2>/dev/null | grep -E '^[0-9]+(\.[0-9]+){3}$' | head -1
  elif have python3; then
    python3 - "$h" <<'PY' 2>/dev/null
import socket,sys
try: print(socket.gethostbyname(sys.argv[1]))
except Exception: pass
PY
  fi
}

# up | timeout | reset
tcp_probe() {
  local ip="$1" port="$2" to="${3:-4}" rc
  with_timeout "$to" bash -c "exec 3<>/dev/tcp/$ip/$port" >/dev/null 2>&1
  rc=$?
  if   [[ $rc -eq 0 ]];                    then echo "up"
  elif [[ $rc -eq 124 || $rc -ge 128 ]];   then echo "timeout"
  else                                          echo "reset"; fi
}

# ok | fail  (TLS-хендшейк; флаги совместимы с LibreSSL)
tls_probe() {
  local ip="$1" port="$2" sni="$3" out
  local args=(s_client -connect "$ip:$port"); [[ -n "$sni" ]] && args+=(-servername "$sni")
  out="$(printf 'Q\n' | with_timeout 8 openssl "${args[@]}" 2>&1)"
  echo "$out" | grep -qiE 'Cipher is|Cipher +:|Protocol +:|Server certificate|SSL-Session|Verify return code|handshake has read' \
    && echo "ok" || echo "fail"
}

now()      { date +%s; }
clock()    { date +%H:%M:%S; }
# секунды -> "Xм Yс"
human()    { local s="$1"; printf '%dм %02dс' $(( s / 60 )) $(( s % 60 )); }

# ---------------------------------------------------------------------------
# Резолв цели
# ---------------------------------------------------------------------------
IP="$(resolve_host "$HOST")"
[[ -z "$IP" ]] && { log_err "Не удалось разрешить $HOST"; exit 1; }
CONTROL_IP="$(resolve_host "$CONTROL_HOST")"

section "Мониторинг блокировки ноды"
log_info "Нода:      $HOST:$PORT  (IP $IP)"
log_info "TLS-проба: $([[ $DO_TLS -eq 1 ]] && echo "да (SNI ${SNI:-<нет>})" || echo нет)"
log_info "Интервал:  ${INTERVAL}с   Длительность: $([[ "$DURATION" -eq 0 ]] && echo '∞ (до Ctrl-C)' || human "$DURATION")"
log_info "Контроль:  $CONTROL_HOST:$CONTROL_PORT${CONTROL_IP:+ (IP $CONTROL_IP)}"
[[ -n "$LOGFILE" ]] && { echo "epoch,time,node_state,reason,control_state,streak_sec" > "$LOGFILE"; log_info "CSV-лог:   $LOGFILE"; }
log_info "Останов — Ctrl-C. Итоги печатаются при выходе."
echo

# ---------------------------------------------------------------------------
# Состояние/статистика
# ---------------------------------------------------------------------------
START="$(now)"
node_state="unknown"          # up | down
last_change="$START"
first_block=0
declare -a block_durs=()      # длительности завершённых DOWN-эпизодов
declare -a up_durs=()         # длительности завершённых UP-эпизодов (между блоками)
declare -a timeline=()        # 'U'/'D' по каждому циклу — для «осциллограммы»
total=0; up_total=0; down_total=0
r_timeout=0; r_reset=0; r_tls=0
ctrl_down=0
STOP=0

on_stop() { STOP=1; }
trap on_stop INT TERM

summarize() {
  local end; end="$(now)"
  # закрыть текущий незавершённый эпизод
  local cur_dur=$(( end - last_change ))
  if [[ "$node_state" == "up" ]];   then up_durs+=("$cur_dur")
  elif [[ "$node_state" == "down" ]]; then block_durs+=("$cur_dur"); fi

  section "ИТОГИ МОНИТОРИНГА"
  local run=$(( end - START ))
  echo "  Длительность наблюдения: $(human "$run")   проб: $total"
  local avail="n/a"
  (( total > 0 )) && avail="$(( up_total * 100 / total ))%"
  echo "  Доступность (UP):        $up_total/$total  ($avail)"
  printf "  Причины DOWN:            timeout=%d  reset=%d%s\n" "$r_timeout" "$r_reset" \
    "$([[ $DO_TLS -eq 1 ]] && printf '  tls=%d' "$r_tls")"
  (( ctrl_down > 0 )) && log_warn "Контрольный хост был недоступен в $ctrl_down проб(ах) — часть простоя может быть общим сбоем канала."

  # «Осциллограмма» доступности
  local tl="" c
  for c in "${timeline[@]}"; do
    [[ "$c" == "U" ]] && tl="${tl}${C_OK}▇${C_RESET}" || tl="${tl}${C_ERR}▁${C_RESET}"
  done
  if [[ -n "$tl" ]]; then
    echo; echo "  Осциллограмма (${C_OK}▇${C_RESET}=UP  ${C_ERR}▁${C_RESET}=DOWN, 1 деление = ${INTERVAL}с):"
    echo -e "  $tl"
  fi

  # Эпизоды блокировок
  local n_ep=${#block_durs[@]}
  echo
  if (( n_ep == 0 )); then
    if (( down_total == 0 )); then
      log_ok "За время наблюдения блокировок НЕ зафиксировано."
      echo "  ${C_DIM}Если блок триггерится объёмом — запустите монитор вместе с реальной нагрузкой${C_RESET}"
      echo "  ${C_DIM}на туннель и/или увеличьте --duration.${C_RESET}"
    else
      log_warn "Были отдельные неудачные пробы, но устойчивых эпизодов блокировки не сложилось."
    fi
    return
  fi

  # статистика по длительностям блоков
  local sum=0 mn=999999 mx=0 d
  for d in "${block_durs[@]}"; do
    sum=$(( sum + d )); (( d < mn )) && mn=$d; (( d > mx )) && mx=$d
  done
  local avg=$(( sum / n_ep ))
  echo "  ${C_HEAD}Эпизодов блокировки: $n_ep${C_RESET}"
  echo "  Длительность блока:  мин $(human "$mn")  /  сред $(human "$avg")  /  макс $(human "$mx")"
  (( first_block > 0 )) && echo "  Time-to-block:       $(human $(( first_block - START ))) от старта"

  # период рабочих окон (между блоками)
  if (( ${#up_durs[@]} > 0 )); then
    local usum=0 umn=999999 umx=0 u
    for u in "${up_durs[@]}"; do usum=$(( usum + u )); (( u < umn )) && umn=$u; (( u > umx )) && umx=$u; done
    echo "  Рабочее окно (UP):   мин $(human "$umn")  /  сред $(human $(( usum / ${#up_durs[@]} )))  /  макс $(human "$umx")"
  fi

  # доминирующая причина блока
  local block_kind="таймаут (пассивный blackhole)"
  (( r_reset > r_timeout )) && block_kind="RST (активный сброс)"

  echo
  echo "  ${C_HEAD}➤ ВЕРДИКТ${C_RESET}"
  if (( ctrl_down * 3 >= down_total && ctrl_down > 0 )); then
    echo "    Простои ноды заметно коррелируют с недоступностью контрольного хоста —"
    echo "    ${C_DIM}возможно, дело в общем канале, а не в точечной блокировке ноды. Проверьте канал.${C_RESET}"
  else
    echo "    Нода периодически блокируется точечно (контроль оставался доступен)."
    echo "    Тип блокировки: преимущественно $block_kind."
    if (( n_ep >= 2 && mn * 2 >= mx )); then
      echo "    Длительности блоков КУЧНЫЕ (${C_HEAD}$(human "$mn")..$(human "$mx")${C_RESET}) → похоже на"
      echo "    penalty-таймер ТСПУ (адаптивная блокировка с фиксированным временем разблокировки)."
    else
      echo "    Разброс длительностей большой — наблюдайте дольше для устойчивого вывода."
    fi
    echo "    ${C_DIM}Обход: Reality/uTLS с валидным SNI, ротация порта/IP, padding и снижение${C_RESET}"
    echo "    ${C_DIM}узнаваемости флоу; для volume-триггера — дробление сессий.${C_RESET}"
  fi
}

# ---------------------------------------------------------------------------
# Основной цикл
# ---------------------------------------------------------------------------
while :; do
  # проба ноды
  reason=""
  st="$(tcp_probe "$IP" "$PORT" 4)"
  if [[ "$st" == "up" && "$DO_TLS" -eq 1 ]]; then
    if [[ "$(tls_probe "$IP" "$PORT" "$SNI")" != "ok" ]]; then st="down"; reason="tls"; fi
  fi
  if [[ "$st" == "up" ]]; then
    cur="up"
  else
    cur="down"
    [[ -z "$reason" ]] && reason="$st"   # timeout|reset
  fi

  # контроль
  cst="down"
  if [[ -n "$CONTROL_IP" ]]; then
    [[ "$(tcp_probe "$CONTROL_IP" "$CONTROL_PORT" 4)" == "up" ]] && cst="up"
  fi

  # учёт
  total=$(( total + 1 ))
  if [[ "$cur" == "up" ]]; then
    up_total=$(( up_total + 1 )); timeline+=("U")
  else
    down_total=$(( down_total + 1 )); timeline+=("D")
    case "$reason" in timeout) r_timeout=$((r_timeout+1));; reset) r_reset=$((r_reset+1));; tls) r_tls=$((r_tls+1));; esac
  fi
  [[ "$cst" == "down" ]] && ctrl_down=$(( ctrl_down + 1 ))

  # переход состояния
  ts="$(now)"
  if [[ "$cur" != "$node_state" ]]; then
    was_unknown=0; [[ "$node_state" == "unknown" ]] && was_unknown=1
    if [[ "$was_unknown" -eq 0 ]]; then
      dur=$(( ts - last_change ))
      if [[ "$node_state" == "up" ]]; then up_durs+=("$dur"); else block_durs+=("$dur"); fi
    fi
    if [[ "$cur" == "down" && "$first_block" -eq 0 ]]; then first_block="$ts"; fi
    node_state="$cur"; last_change="$ts"
    if [[ "$was_unknown" -eq 1 ]]; then
      # самое первое измерение — стартовое состояние, без «снова»
      if [[ "$cur" == "up" ]]; then
        log_ok  "$(clock)  старт: нода доступна${C_DIM}  [контроль: $cst]${C_RESET}"
      else
        log_err "$(clock)  старт: нода НЕдоступна ($reason)${C_DIM}  [контроль: $cst]${C_RESET}"
      fi
    elif [[ "$cur" == "down" ]]; then
      log_err "$(clock)  НОДА ЗАБЛОКИРОВАНА ($reason)${C_DIM}  [контроль: $cst]${C_RESET}"
    else
      # длительность только что закончившегося блока
      last_block=0; (( ${#block_durs[@]} > 0 )) && last_block="${block_durs[${#block_durs[@]}-1]}"
      log_ok  "$(clock)  нода снова доступна${C_DIM}  (блок длился $(human "$last_block"))${C_RESET}"
    fi
  else
    streak=$(( ts - last_change ))
    if [[ "$cur" == "up" ]]; then
      echo "${C_DIM}$(clock)  UP    (стрик $(human "$streak"))  контроль:$cst${C_RESET}"
    else
      echo "${C_DIM}$(clock)  DOWN  $reason  (уже $(human "$streak"))  контроль:$cst${C_RESET}"
    fi
  fi

  # CSV
  if [[ -n "$LOGFILE" ]]; then
    echo "$ts,$(clock),$cur,${reason:-},$cst,$(( ts - last_change ))" >> "$LOGFILE"
  fi

  # условия останова
  [[ "$STOP" -eq 1 ]] && break
  if [[ "$DURATION" -ne 0 ]] && (( ts - START >= DURATION )); then break; fi

  sleep "$INTERVAL"
  [[ "$STOP" -eq 1 ]] && break
done

summarize
