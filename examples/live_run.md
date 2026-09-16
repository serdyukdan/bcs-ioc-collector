# Результат сетевого запуска

Последняя успешная загрузка: **2026-09-16T17:15:25.381597Z**. Сбор выполнен на Python 3.12.14,
SQLite 3.53.1. Все три поставщика успешно обработаны, код завершения — 0.

Всего **577163** уникальных IoC: **64 Critical**,
**8786 High**, **568313 Medium**.
Типы: domain: 527040, ipv4: 49394, ipv6: 729.

| Источник | Уникальных IoC | Отклонённых строк | Статус |
| --- | ---: | ---: | --- |
| blocklist_de | 26222 | 0 | ok |
| cins_army | 15000 | 0 | ok |
| threatview | 544855 | 55 | ok |

ThreatView загружался из двух фидов: IP и домены. Число его индикаторов — сумма
валидных уникальных значений из обоих файлов. Числа у поставщиков не складываются
в итог напрямую из-за пересечений.

Ниже — сохранённый stdout реальных запросов, по три записи каждого уровня.
Показаны команды с путём БД по умолчанию; при проверке использовался временный
файл с тем же содержимым и явный аргумент `--db`. Значения приводятся как данные,
без перехода на адреса или резолвинга доменов. Это содержимое сторонних фидов,
а не самостоятельное заключение о вредоносности адресов.

```text
python ioc.py --level critical --limit 3
value	type	source_count	level	sources	updated_at
100.55.80.54	ipv4	3	Critical	blocklist_de,cins_army,threatview	2026-09-16T17:15:25.381597Z
103.163.46.207	ipv4	3	Critical	blocklist_de,cins_army,threatview	2026-09-16T17:15:25.381597Z
103.182.18.193	ipv4	3	Critical	blocklist_de,cins_army,threatview	2026-09-16T17:15:25.381597Z
```
```text
python ioc.py --level high --limit 3
value	type	source_count	level	sources	updated_at
1.10.172.57	ipv4	2	High	cins_army,threatview	2026-09-16T17:15:25.381597Z
1.161.8.206	ipv4	2	High	blocklist_de,threatview	2026-09-16T17:15:25.381597Z
1.231.81.166	ipv4	2	High	blocklist_de,threatview	2026-09-16T17:15:25.381597Z
```
```text
python ioc.py --level medium --limit 3
value	type	source_count	level	sources	updated_at
0-0asia.com	domain	1	Medium	threatview	2026-09-16T17:15:25.381597Z
0-0x.xyz	domain	1	Medium	threatview	2026-09-16T17:15:25.381597Z
0-9u210edu12j-dj-1.xyz	domain	1	Medium	threatview	2026-09-16T17:15:25.381597Z
```

У БД проверены `PRAGMA integrity_check`, `PRAGMA foreign_key_check` и равенство
сохранённого `source_count` числу уникальных связей с поставщиками для всех записей.
Сохранённая полная статистика источников: `live_stats.json`.
При повторном запуске состав и размеры фидов могут измениться.
