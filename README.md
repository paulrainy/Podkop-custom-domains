# Podkop-custom-domains

## recon.sh

Скрипт для пассивного сбора доменов и поддоменов сервиса. Агрегирует данные из 8 бесплатных источников (запрашиваются параллельно, с ретраями при сетевых сбоях), дедуплицирует и валидирует результаты через DNS.

Предназначен для формирования списков доменов для [Podkop](https://github.com/itdoginfo/podkop).

### Зависимости

| Инструмент | Установка | Назначение |
|---|---|---|
| `subfinder` | `brew install subfinder` | Пассивная разведка поддоменов |
| `dnsx` | `brew install dnsx` | DNS-валидация доменов |
| `curl` | встроен в macOS | HTTP-запросы к API |
| `jq` | `brew install jq` | Парсинг JSON |
| `dig` | встроен в macOS | DNS-запросы |

Если инструменты не установлены — скрипт установит их сам (`brew` на macOS; на Linux системные тулы `curl`/`jq`/`dig` ставятся через `apt`/`pacman`/`dnf`, а для `subfinder`/`dnsx` скрипт подскажет `go install ...`, т.к. для них нет системного пакета).

### Использование

```bash
chmod +x recon.sh

# Базовый запуск (результаты в ./recon-<domain>/)
./recon.sh context7.com

# С указанием директории вывода
./recon.sh xda-developers.com ./xda-recon

# Сравнить с предыдущим запуском в тот же output_dir (см. "Режим --diff" ниже)
./recon.sh context7.com ./recon-context7.com --diff
```

### Источники данных

Источники опрашиваются параллельно (фоновыми задачами), с ретраями (до 3 попыток с задержкой) при сетевых сбоях; результаты объединяются и дедуплицируются:

| # | Источник | Описание |
|---|---|---|
| 1 | **subfinder** | ~30 пассивных источников: VirusTotal, Shodan, HackerTarget, crt.sh и др. |
| 2 | **crt.sh** | Certificate Transparency логи |
| 3 | **Certspotter** | CT логи (резервный источник, работает когда crt.sh недоступен) |
| 4 | **HackerTarget** | Публичная база DNS |
| 5 | **URLScan.io** | Публичные сканы веб-страниц |
| 6 | **Wayback Machine** | CDX API web.archive.org |
| 7 | **AlienVault OTX** | Passive DNS |
| 8 | **RapidDNS.io** | HTML-скрейпинг публичной базы поддоменов (без API-ключа) |
| 9 | **dig** | MX, NS, TXT записи основного домена |

Также рассматривались **ProjectDiscovery Chaos** и **DNSDumpster**, но не были добавлены: Chaos индексирует только домены bug-bounty программ (не подходит для произвольного домена), а DNSDumpster теперь требует API-ключ — оба нарушают принцип "без ключей" этого проекта.

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
├── alienvault.txt           # Сырой вывод alienvault otx
└── rapiddns.txt             # Сырой вывод rapiddns.io
```

При запуске с `--diff` дополнительно появляются `all_domains.prev.txt` (снимок предыдущего запуска), `all_domains.new.txt` (новые домены) и, если был предыдущий запуск, `all_domains.gone.txt` (пропавшие домены).

**Для Podkop использовать `all_domains.txt`** — он содержит только домены, которые реально резолвятся в DNS.

### Режим `--diff`

Флаг `--diff` сравнивает свежий результат с предыдущим запуском в том же `output_dir` (снимок берётся по файлу, а не по git), чтобы не пересматривать вручную весь список ради новых доменов:

```bash
./recon.sh context7.com ./recon-context7.com --diff
```

Если появились новые домены — они печатаются в разделе "Diff vs previous run", попадают в `all_domains.new.txt`, а скрипт завершается с кодом выхода `2` (удобно для скриптов вроде `update-all.sh`, см. ниже). Без новых доменов — код выхода `0`. Без флага `--diff` поведение и код выхода не меняются.

### Массовое обновление всех таргетов (`update-all.sh`)

`update-all.sh` перезапускает `recon.sh --diff` для каждой папки, перечисленной в `targets.conf` (карта `папка → домен(ы)`, включая многокорневые таргеты вроде `brawlstars-recon`), и в конце печатает список таргетов, где появились новые домены:

```bash
# Посмотреть, что будет запущено, без единого сетевого запроса
./update-all.sh --dry-run

# Реальное обновление всех таргетов
./update-all.sh
```

⚠️ Один прогон `update-all.sh` расходует общий дневной лимит источников (например, HackerTarget: 50 запросов/день) сразу на все таргеты — не запускай его чаще одного раза в день.

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
