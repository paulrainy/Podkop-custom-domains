# Podkop-custom-domains

## list.txt

Простой список доменов, которых не хватает среди уже существующих списков для [Podkop](https://github.com/itdoginfo/podkop). Будет регулярно обновляться. Если полный список не нужен - в директориях имеются файлы `all_domains.txt`, их можно использовать в подкопе.

## recon.sh

Скрипт для пассивного сбора доменов и поддоменов сервиса. Агрегирует данные из 7 бесплатных источников, дедуплицирует и валидирует результаты через DNS.

Предназначен для формирования списков доменов для [Podkop](https://github.com/itdoginfo/podkop).

### Зависимости

| Инструмент | Установка | Назначение |
|---|---|---|
| `subfinder` | `brew install subfinder` | Пассивная разведка поддоменов |
| `dnsx` | `brew install dnsx` | DNS-валидация доменов |
| `curl` | встроен в macOS | HTTP-запросы к API |
| `jq` | `brew install jq` | Парсинг JSON |
| `dig` | встроен в macOS | DNS-запросы |

Если инструменты не установлены — скрипт установит их сам через `brew`.

### Использование

```bash
chmod +x recon.sh

# Базовый запуск (результаты в ./recon-<domain>/)
./recon.sh context7.com

# С указанием директории вывода
./recon.sh xda-developers.com ./xda-recon
```

### Источники данных

Скрипт последовательно опрашивает все источники, объединяет результаты и удаляет дубликаты:

| # | Источник | Описание |
|---|---|---|
| 1 | **subfinder** | ~30 пассивных источников: VirusTotal, Shodan, HackerTarget, crt.sh и др. |
| 2 | **crt.sh** | Certificate Transparency логи |
| 3 | **Certspotter** | CT логи (резервный источник, работает когда crt.sh недоступен) |
| 4 | **HackerTarget** | Публичная база DNS |
| 5 | **URLScan.io** | Публичные сканы веб-страниц |
| 6 | **Wayback Machine** | CDX API web.archive.org |
| 7 | **AlienVault OTX** | Passive DNS |
| 8 | **dig** | MX, NS, TXT записи основного домена |

После сбора все кандидаты проверяются через `dnsx` — в итоговый файл попадают только домены, у которых есть A-запись в DNS.

### Файлы результатов

После выполнения в директории вывода (`./recon-<domain>/` по умолчанию):

```
recon-context7.com/
├── all_domains.txt          # Живые домены — использовать в Podkop
├── all_domains_with_ip.txt  # Живые домены с IP-адресами
├── all_raw.txt              # Все кандидаты до валидации
├── subfinder.txt            # Сырой вывод subfinder
├── crtsh.txt                # Сырой вывод crt.sh
├── certspotter.txt          # Сырой вывод certspotter
├── hackertarget.txt         # Сырой вывод hackertarget
├── urlscan.txt              # Сырой вывод urlscan
├── wayback.txt              # Сырой вывод wayback machine
└── alienvault.txt           # Сырой вывод alienvault otx
```

**Для Podkop использовать `all_domains.txt`** — он содержит только домены, которые реально резолвятся в DNS.

### Пример вывода

```
══ subfinder (passive) ══
[*] Running subfinder on context7.com ...
[+] subfinder: 35 domains

══ crt.sh (Certificate Transparency) ══
[*] Querying crt.sh for %.context7.com ...
[+] crt.sh: 10 domains

...

══ DNS validation (dnsx) ══
[*] Validating 36 candidates ...
[+] Alive: 8  |  Dead (no DNS): 28

══ Summary ══
Target:     context7.com
Output:     ./recon-context7.com/

Live domains:
accounts.context7.com
clerk.context7.com
context7.com
mcp.context7.com
...

[+] Done. Use ./recon-context7.com/all_domains.txt for Podkop.
```

### Ограничения

- Все источники **бесплатны и не требуют API-ключей**, но имеют rate limits. Не запускай скрипт на один домен чаще чем раз в несколько часов.
- `crt.sh` периодически недоступен — в этом случае скрипт продолжает работу с остальными источниками.
- HackerTarget бесплатный tier ограничен 50 запросами в день.
- Скрипт собирает только поддомены указанного домена. Для поиска других TLD организации (`.io`, `.ai` и т.д.) — проверь вручную через `dig +short context7.io A`.
- Внутренние/служебные домены (staging, grafana, vpn и т.п.) попадут в `all_raw.txt` — не добавляй их в Podkop без необходимости.
