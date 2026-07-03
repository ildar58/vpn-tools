# vpn-tools

Утилиты для обслуживания VPN VPS.

## Скрипт hardening + geo update (v2, идемпотентный)

Файл: `vps-hardening-and-geo.sh`

### Что делает

1. Применяет UFW-правила:
   - deny in: `25/tcp`, `587/tcp`, `465/tcp`
   - deny out: `25/tcp`, `587/tcp`, `465/tcp`
   - allow: `443/tcp`, `22/tcp`, `80/tcp`
   - allow IP rules:
     - `84.200.193.142 -> 2222`
     - `109.122.199.37 -> 9999`
     - `81.200.151.202 -> 9999`
     - `95.85.240.116 -> 9999`
   - default deny incoming
   - включает и активирует `ufw`

2. Выполняет обновление системы:
   - `apt update && apt upgrade -yqq`

3. Создаёт `/usr/local/bin/update-xray-geo.sh`, который:
   - скачивает `geosite.dat` и `geoip.dat`
   - кладёт в `/opt/remnanode/xray/share`
   - перезапускает `docker` контейнер `remnanode`

4. Добавляет cron:
   - `0 7 * * * /usr/local/bin/update-xray-geo.sh`

5. Сразу запускает `/usr/local/bin/update-xray-geo.sh`.

## Особенности v2

- Скрипт рассчитан на безопасный повторный запуск.
- UFW-правила добавляются с проверкой существования (без лишних дублей).
- Cron-строка пересобирается без дублирования.
- Добавлены явные проверки необходимых команд и более читаемые логи.

## Запуск

> Запускать от root (или через sudo).

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ildar58/vpn-tools/main/vps-hardening-and-geo.sh)
```

## Анализатор уровня блокировки подключения к xray-ноде

Файл: `xray-block-analyzer.sh`

Запускается **со стороны клиента** (например, из РФ) и определяет, на каком
уровне рвётся TCP-подключение к xray-ноде. Поиск ноды по домену (приоритетно),
поддерживается и `ip:порт`.

### Быстрый запуск

> Замените `node.example.com` на домен (или `ip:порт`) вашей ноды.

```bash
curl -fsSL https://raw.githubusercontent.com/ildar58/vpn-tools/main/xray-block-analyzer.sh | sudo bash -s -- node.example.com
```

### Что проверяет (по уровням)

1. **DNS** — сравнивает ответ системного резолвера, внешних UDP-резолверов
   (`8.8.8.8`, `1.1.1.1`) и **DoH** (DNS-over-HTTPS как незасоряемый эталон).
   Ловит: подмену ответа (fake answer), прозрачный перехват UDP/53,
   дроп/NXDOMAIN на заблокированный домен.
2. **L3 / IP** — ICMP-ping и TCP-`traceroute`: определяет блэкхол/нуль-роут IP
   и хоп, после которого гибнут пакеты.
3. **L4 / TCP** — множественные пробы хендшейка: различает **таймаут** (пассивный
   дроп SYN) и **RST/refused** (активный сброс). Сверяет с другими портами того же
   IP — блокировка порт-специфична или на весь IP.
4. **Инъекция RST от DPI** (root + `tcpdump`) — **TTL-анализ**: сравнивает TTL
   RST-пакетов с TTL «живых» пакетов сервера. Несовпадение → RST подделан
   посредником (DPI), а не прислан самой нодой.
5. **L7 / TLS (SNI)** — TLS-хендшейк с целевым SNI против безобидного SNI на
   том же `IP:порт`. Вычленяет блокировку именно по SNI (DPI на ClientHello).
6. **Контроль канала** — TCP+TLS до публичного хоста, чтобы отделить проблему
   ноды от общей неработоспособности интернета.

В конце — сводная таблица и **вердикт** с указанием уровня блокировки и вариантов
обхода.

### Особенности

- Для максимальной диагностики (TTL-анализ RST) нужен **root** и `tcpdump` —
  скрипт предложит доустановить недостающие инструменты (`dig`, `traceroute`,
  `tcpdump`). Без root базовые проверки всё равно выполняются.
- Безопасен: только читает сеть, ничего не меняет на клиенте и на ноде.

### Запуск

```bash
# по домену (порт по умолчанию 443)
sudo bash xray-block-analyzer.sh node.example.com

# домен с портом
sudo bash xray-block-analyzer.sh node.example.com:2053

# по IP с явным SNI
sudo bash xray-block-analyzer.sh 203.0.113.10 443 --sni www.microsoft.com

# или прямо из репозитория
sudo bash <(curl -fsSL https://raw.githubusercontent.com/ildar58/vpn-tools/main/xray-block-analyzer.sh) node.example.com
```

Опции: `--sni <name>`, `--control <host[:port]>`, `--attempts N`, `--no-install`.
