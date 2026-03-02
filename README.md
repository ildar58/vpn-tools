# vpn-tools

Утилиты для обслуживания VPN VPS.

## Скрипт hardening + geo update

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

## Запуск

> Запускать от root (или через sudo).

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ildar58/vpn-tools/main/vps-hardening-and-geo.sh)
```
