# Live Packet Sniffer (Windows, Python, Scapy, Rich)

Консольный live-сниффер сетевых пакетов для учебного использования в локальной сети.

Программа:
- перехватывает пакеты с интерфейса;
- показывает последние пакеты в обновляемой таблице;
- считает статистику `TCP / UDP / ICMP / Total`;
- сохраняет лог после завершения в `txt` или `json`.

## Важно

Используйте только в своей локальной сети или с явного разрешения владельца сети.

## Требования

- Windows 10/11
- Python 3.x
- [Npcap](https://npcap.com/) или WinPcap
- Права администратора для запуска сниффера
- Зависимости Python:
  - `scapy`
  - `rich`

## Если Python не установлен

1. Скачайте Python с официального сайта: https://www.python.org/downloads/windows/
2. Запустите установщик.
3. На первом экране обязательно включите опцию:
   - `Add python.exe to PATH`
4. Нажмите `Install Now`.
5. После установки перезапустите PowerShell и проверьте:

```powershell
python --version
py --version
```

Если команда `python` не найдена, используйте `py`:

```powershell
py --version
```

## Если uv не установлен

Проверьте наличие:

```powershell
uv --version
```

Если команда не найдена, установите `uv`:

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

После установки:

1. Закройте и заново откройте PowerShell.
2. Снова проверьте:

```powershell
uv --version
```

Если в текущей сессии `uv` все еще не найден, добавьте путь вручную:

```powershell
$env:Path = "C:\Users\<USER>\.local\bin;$env:Path"
```

## Установка Npcap (где и как)

Ставьте Npcap только с официального сайта:

- Главная страница: https://npcap.com/
- Документация: https://npcap.com/guide/npcap-users-guide.html

Порядок установки на Windows:

1. Скачайте актуальный инсталлятор с `npcap.com`.
2. Запустите установщик **от имени администратора**.
3. Во время установки:
   - рекомендуется **не включать** `WinPcap compatibility mode` (рекомендация Scapy);
   - опцию `802.11` включайте только если нужен Wi‑Fi monitor mode и адаптер это поддерживает.
4. Завершите установку.
5. Если установщик попросил перезагрузку, перезагрузите ПК.

Справка Scapy по Windows/Npcap:

- https://scapy.readthedocs.io/en/latest/installation.html

## Как проверить, что Npcap установлен и работает

### 1) Проверка через службу Windows

Откройте PowerShell **от имени администратора** и выполните:

```powershell
sc.exe query npcap
```

Ожидаемо:
- служба `npcap` существует;
- состояние `RUNNING` или служба может быть запущена вручную.

Если не запущена, попробуйте:

```powershell
net start npcap
```

### 2) Проверка файлов установки

Проверьте наличие каталога:

```text
C:\Program Files\Npcap\
```

Полезные диагностические файлы:

- `C:\Program Files\Npcap\DiagReport.bat`
- `C:\Program Files\Npcap\install.log`
- `C:\Program Files\Npcap\NPFInstall.log`

### 3) Практическая проверка с вашим сниффером

Запустите от администратора короткий тест:

```powershell
.\.venv\Scripts\python.exe sniffer.py --count 10
```

Признаки, что все работает:
- в live-таблице появляются пакеты;
- растут счетчики `TCP/UDP/ICMP/Total`;
- после завершения создается лог-файл.

Если пакетов нет:
- проверьте, что запуск идет от администратора;
- попробуйте указать интерфейс явно (`--iface "Ethernet"` или `--iface "Wi-Fi"`);
- создайте трафик (например, откройте сайт в браузере) и повторите запуск.

## Быстрый старт (через uv)

Из корня проекта `d:\git\sniffer`:

```powershell
uv venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Если `uv` не находится в PowerShell, добавьте путь в текущую сессию:

```powershell
$env:Path = "C:\Users\<USER>\.local\bin;$env:Path"
```

## Запуск

Откройте **PowerShell от имени администратора** и выполните:

```powershell
.\.venv\Scripts\python.exe sniffer.py --count 100
```

Пример с фильтрами:

```powershell
.\.venv\Scripts\python.exe sniffer.py --count 100 --protocol tcp --port 443
```

## Аргументы CLI

```text
-i, --iface            Сетевой интерфейс (опционально)
-c, --count            Количество пакетов (0 = без лимита)
--filter               Raw BPF-фильтр для Scapy
--protocol             tcp | udp | icmp
--port                 Порт (1..65535)
--max-rows             Сколько последних пакетов показывать в таблице
--log-file             Путь файла лога
--log-format           txt | json
```

Проверка всех опций:

```powershell
.\.venv\Scripts\python.exe sniffer.py --help
```

## Логика фильтрации

Финальный BPF-фильтр собирается из `--filter`, `--protocol`, `--port`:

- только `--protocol tcp` -> `(tcp)`
- `--protocol tcp --port 443` -> `(tcp port 443)`
- только `--port 53` -> `(tcp port 53 or udp port 53)`
- `--filter "host 8.8.8.8" --protocol udp` -> `(host 8.8.8.8) and (udp)`

Ограничение:
- `--protocol icmp --port ...` недопустимо (порт для ICMP не применяется).

## Что отображается в live-таблице

Колонки:
- `Time` — время пакета (`HH:MM:SS`)
- `Proto` — `TCP`, `UDP`, `ICMP`, `OTHER`
- `Source` — `IP[:port]`
- `Destination` — `IP[:port]`
- `Flags` — TCP-флаги (для не-TCP: `-`)
- `Size` — размер пакета в байтах

Под таблицей выводится текущая статистика:

```text
TCP: X | UDP: Y | ICMP: Z | Total: N
```

## Завершение работы

- Если задан `--count > 0`, захват завершится автоматически.
- Если `--count 0`, остановите вручную через `Ctrl+C`.
- После завершения всегда выводится финальная статистика и путь к файлу лога.

## Формат логов

### TXT

Одна строка = один пакет:

```text
12:31:01 | TCP   | 192.168.1.10:53321 -> 142.250.185.78:443 | Flags: S | Size: 66
```

### JSON

Массив объектов:

```json
[
  {
    "time": "12:31:01",
    "proto": "TCP",
    "source": "192.168.1.10:53321",
    "destination": "142.250.185.78:443",
    "flags": "S",
    "size": 66
  }
]
```

Если `--log-file` не задан, имя генерируется автоматически:

```text
sniffer_log_YYYYMMDD_HHMMSS.txt
```
или
```text
sniffer_log_YYYYMMDD_HHMMSS.json
```

## Примеры использования

Ниже собраны команды по всем флагам из `--help`, чтобы можно было проверить каждый режим.

### Базовые команды

Показать справку:

```powershell
.\.venv\Scripts\python.exe sniffer.py --help
```

Запуск с параметрами по умолчанию:

```powershell
.\.venv\Scripts\python.exe sniffer.py
```

Указать интерфейс (`--iface`):

```powershell
.\.venv\Scripts\python.exe sniffer.py --iface "Ethernet"
```

Ограничить число пакетов (`--count`):

```powershell
.\.venv\Scripts\python.exe sniffer.py --count 50
```

Без лимита пакетов (`--count 0`, остановка `Ctrl+C`):

```powershell
.\.venv\Scripts\python.exe sniffer.py --count 0
```

### Фильтрация трафика

Raw BPF-фильтр (`--filter`):

```powershell
.\.venv\Scripts\python.exe sniffer.py --filter "host 8.8.8.8"
```

Только TCP (`--protocol tcp`):

```powershell
.\.venv\Scripts\python.exe sniffer.py --protocol tcp --count 200
```

Только UDP (`--protocol udp`):

```powershell
.\.venv\Scripts\python.exe sniffer.py --protocol udp --count 200
```

Только ICMP (`--protocol icmp`):

```powershell
.\.venv\Scripts\python.exe sniffer.py --protocol icmp --count 200
```

Фильтр по порту без протокола (`--port` применится к TCP/UDP):

```powershell
.\.venv\Scripts\python.exe sniffer.py --port 53 --count 100
```

TCP на конкретном порту (`--protocol tcp --port`):

```powershell
.\.venv\Scripts\python.exe sniffer.py --protocol tcp --port 443 --count 100
```

UDP на конкретном порту (`--protocol udp --port`):

```powershell
.\.venv\Scripts\python.exe sniffer.py --protocol udp --port 53 --count 100
```

ICMP без лимита (остановка `Ctrl+C`):

```powershell
.\.venv\Scripts\python.exe sniffer.py --protocol icmp --count 0
```

Комбинация `--filter` + `--protocol`:

```powershell
.\.venv\Scripts\python.exe sniffer.py --filter "host 8.8.8.8" --protocol udp --count 100
```

Комбинация `--filter` + `--port`:

```powershell
.\.venv\Scripts\python.exe sniffer.py --filter "net 192.168.1.0/24" --port 53 --count 100
```

Комбинация `--filter` + `--protocol` + `--port`:

```powershell
.\.venv\Scripts\python.exe sniffer.py --filter "host 1.1.1.1" --protocol tcp --port 443 --count 100
```

### Отображение и логирование

Показать больше строк в live-таблице (`--max-rows`):

```powershell
.\.venv\Scripts\python.exe sniffer.py --count 100 --max-rows 50
```

Сохранить лог в конкретный файл (`--log-file`):

```powershell
.\.venv\Scripts\python.exe sniffer.py --count 100 --log-file logs\capture.txt
```

Сохранить лог в JSON (`--log-format json`):

```powershell
.\.venv\Scripts\python.exe sniffer.py --count 100 --log-format json
```

Одновременно `--log-file` и `--log-format`:

```powershell
.\.venv\Scripts\python.exe sniffer.py --count 100 --log-file logs\capture_443 --log-format json
```

Полный пример со всеми основными флагами:

```powershell
.\.venv\Scripts\python.exe sniffer.py --iface "Ethernet" --count 200 --filter "host 8.8.8.8" --protocol tcp --port 443 --max-rows 30 --log-file logs\session_01 --log-format json
```

### Невалидная комбинация (ожидаемая ошибка)

`--protocol icmp` нельзя использовать вместе с `--port`:

```powershell
.\.venv\Scripts\python.exe sniffer.py --protocol icmp --port 53
```

## Структура проекта

- `sniffer.py` — основной скрипт live-сниффера
- `requirements.txt` — зависимости Python
- `REPORT.md` — краткий отчет по заданию
- `PLANS.md` / `STATUS.md` / `NOTES.md` — рабочие файлы процесса разработки

## Подробное объяснение кода (для отчета)

Ниже описание логики программы по функциям и шагам выполнения.

### Общая архитектура

Программа разделена на 4 части:
- парсинг аргументов и валидация CLI;
- перехват и разбор пакетов (Scapy);
- live-рендер таблицы и статистики (Rich);
- сохранение результатов в файл (`txt`/`json`).

### Модель данных

`PacketRecord` (`dataclass`) хранит одну запись пакета:
- `time` — время пакета;
- `proto` — протокол (`TCP/UDP/ICMP/OTHER`);
- `source` — источник (`IP` или `IP:port`);
- `destination` — назначение (`IP` или `IP:port`);
- `flags` — TCP-флаги или `-`;
- `size` — размер пакета в байтах.

### Класс состояния `SnifferState`

`SnifferState` инкапсулирует состояние текущей сессии сниффинга.

Что хранит:
- `_recent` — кольцевой буфер последних N пакетов (`deque(maxlen=max_rows)`) для таблицы;
- `_all_records` — полный список пакетов для сохранения в лог;
- `_stats` — счетчики `TCP/UDP/ICMP/Total`;
- `_lock` — `threading.Lock` для потокобезопасности.

Методы:
- `add(record)`:
  - добавляет запись в `_recent` и `_all_records`;
  - увеличивает `Total`;
  - увеличивает счетчик соответствующего протокола.
- `snapshot()`:
  - возвращает копии текущих строк таблицы и статистики.
- `all_records()`:
  - возвращает копию полного списка пакетов для экспорта.

Почему нужен `Lock`:
- `AsyncSniffer` вызывает callback из отдельного потока;
- main-поток одновременно читает данные для рендера;
- без блокировки возможны race condition и поврежденные структуры.

### CLI и валидация

`parse_args()`:
- объявляет все аргументы:
  - `--iface`, `--count`, `--filter`, `--protocol`, `--port`,
  - `--max-rows`, `--log-file`, `--log-format`;
- проверяет ограничения:
  - `count >= 0`;
  - `max-rows > 0`;
  - `port` в диапазоне `1..65535`;
  - запрет `--protocol icmp` вместе с `--port`.

Если аргументы некорректны, программа завершится с понятным сообщением `SystemExit`.

### Построение BPF-фильтра

`build_capture_filter(args)`:
- собирает итоговую строку фильтра для Scapy (`filter=...`);
- если задан `--filter`, берет его как базовый блок;
- дополняет условиями `--protocol` и `--port`;
- объединяет условия через `and`.

Примеры:
- `--protocol tcp` -> `(tcp)`
- `--protocol tcp --port 443` -> `(tcp port 443)`
- `--port 53` -> `(tcp port 53 or udp port 53)`

### Разбор пакета

`packet_to_record(packet)` превращает Scapy-пакет в `PacketRecord`.

Шаги:
1. Вычисляет время:
   - пытается использовать `packet.time`;
   - при ошибке берет текущее время `datetime.now()`.
2. Инициализирует значения по умолчанию (`OTHER`, `-`, без портов).
3. Если есть `IP`:
   - берет `src`, `dst`, `proto`.
4. Если есть `TCP`:
   - протокол принудительно `TCP`;
   - извлекает `sport`, `dport`, `flags`.
5. Иначе если есть `UDP`:
   - протокол `UDP`;
   - извлекает `sport`, `dport`.
6. Иначе если есть `ICMP`:
   - протокол `ICMP`.
7. Размер пакета = `len(packet)`.
8. Возвращает заполненный `PacketRecord`.

Дополнительные функции:
- `ip_proto_name(proto_number)` — маппинг IP proto number -> имя протокола;
- `format_endpoint(ip, port)` — форматирует `IP[:port]`.

### Рендер live-таблицы

`render_dashboard(rows, stats)`:
- создает `rich.Table` с колонками:
  - `Time`, `Proto`, `Source`, `Destination`, `Flags`, `Size`;
- добавляет строки из `rows`;
- формирует строку статистики:
  - `TCP: x | UDP: y | ICMP: z | Total: n`;
- возвращает `Group(table, Text(stats_line))` для `Live`.

### Сохранение логов

Функции:
- `default_log_path(log_format)`:
  - генерирует имя `sniffer_log_YYYYMMDD_HHMMSS.<ext>`.
- `resolve_log_path(log_file, log_format)`:
  - использует путь из `--log-file` или автогенерирует;
  - при отсутствии расширения добавляет его по `--log-format`.
- `save_txt(path, records)`:
  - пишет по одной человекочитаемой строке на пакет.
- `save_json(path, records)`:
  - сохраняет массив объектов (`asdict(PacketRecord)`).
- `save_records(...)`:
  - выбирает `save_txt` или `save_json`.

### Основной сценарий `main()`

1. Читает аргументы (`parse_args`) и строит фильтр (`build_capture_filter`).
2. Создает `SnifferState` и `rich.Console`.
3. Объявляет callback `on_packet(packet)`:
   - конвертирует пакет в `PacketRecord`;
   - добавляет запись в состояние;
   - при ошибке в callback мягко игнорирует пакет, не падая всем процессом.
4. Создает `AsyncSniffer` с параметрами:
   - `prn=on_packet`, `store=False`, `count`, `iface`, `filter`.
5. Запускает `Live(...)` и `sniffer.start()`.
6. В цикле каждые `0.5` секунды:
   - берет `snapshot()` состояния;
   - обновляет таблицу `live.update(...)`;
   - проверяет условия завершения по лимиту и состоянию sniffer.
7. При `Ctrl+C`:
   - ставит флаг `interrupted=True`;
   - в `finally` останавливает sniffer (`sniffer.stop()`), если еще запущен.
8. После выхода:
   - сохраняет полный лог (`save_records`);
   - печатает финальную статистику и путь к файлу.

### Как это выглядит во время работы

1. Пользователь запускает скрипт с нужными фильтрами.
2. Scapy перехватывает пакеты.
3. Каждый пакет проходит через `on_packet -> packet_to_record -> state.add`.
4. `Live` обновляет таблицу в терминале в реальном времени.
5. По `count` или `Ctrl+C` захват останавливается.
6. Лог сохраняется на диск, печатается итоговая статистика.
