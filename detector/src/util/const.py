"""
Этот файл содержит константы, которые используются в других частях приложения.
Если вы не знаете, что делаете, то не стоит изменять никаких значений.

Всё, что можно изменять, находится в файле `settings.ini`.
Подробнее — в файле `README.md` или в самом файле `settings.ini`.
"""

import os, subprocess
from main import settings

# Базовая директория проекта, без `/` в конце.
# Похоже, что `os.getcwd()` - не лучший способ получить базовую директорию.
# Он бы не работал, если бы вы запускали приложение из другой директории или
# используя абсолютный путь.
# См. https://stackoverflow.com/a/5137509/1320237
# К сожалению, вам нужно будет изменить этот путь, если вы перенесете этот
# файл (const.py) в другое место.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Директория для проекта LUCID, содержащая модель LUCID и инструменты для
# работы с ней.
LUCID_DIR = os.path.join(BASE_DIR, "lucid")

# Директория, в которой сохраняется обученная модель LUCID.
LUCID_MODEL_DIR = os.path.join(LUCID_DIR, "model")

# Это - директория, в которой сохраняются CSV-файлы со сводкой,
# сгенерированной LUCID.
# Значение этой переменной не должно изменяться, поскольку в LUCID
# захардкожен путь "<текущая_папка>/output" для сохранения CSV-файлов.
CSV_OUTPUT_DIR = os.path.join(os.getcwd(), "output")

# Путь к файлу, в котором содержится наиболее частый IP-адрес отправителя.
# Мы сохраним этот файл в той же директории, в которой модель генерирует
# CSV-файлы, просто создав новую поддиректорию.
MOST_FREQUENT_SENDER_FILE_PATH = os.path.join(
    CSV_OUTPUT_DIR, "most_frequent_sender", "most_frequent_sender.txt"
)

# Это - пути к директории, в которой будут сохранены все PCAP-файлы
# (файлы захвата, сгенерированные tshark).
if os.name == "nt":
    # Windows, это будет выглядеть так: `C:\Users\user\AppData\Local\Temp\lucid`
    PCAP_DIR = os.path.join(os.environ.get("TEMP"), "lucid")
else:
    # Unix-подобные системы, будет выглядеть так: `/tmp/lucid`
    PCAP_DIR = "/tmp/lucid"

# Определяет базовое имя PCAP-файла.
# К нему будет добавлено время захвата.
PCAP_FILENAME = "mycapture"

# Определяет имя объединенного PCAP-файла из всех захваченных файлов.
MERGED_PCAP_FILENAME = "merged"

# Определяет пример, по которому будет сформирован путь к файлу захвата.
# Здесь не нужно указывать расширение файла или время захвата, они будут
# добавлены автоматически.
# Пример: `/tmp/lucid/mycapture`
PCAP_FILEPATH_SCHEMA = os.path.join(PCAP_DIR, PCAP_FILENAME)

# Определяет сетевой интерфейс (или несколько интерфейсов),
# который будет использоваться для захвата трафика.
LUCID_INTERFACES = (
    # Если мы используем Unix-подобную ОС, мы можем использовать
    # `ip route` для получения имени интерфейса по умолчанию.
    # Пример вывода: `enp1s0`, `eth0` или `wlp3s0`.
    # Разделяем строку на список, чтобы получить имена нескольких
    # интерфейсов.
    subprocess.check_output("ip route | grep default | awk '{print $5}'", shell=True)
    .decode("utf-8")
    .strip()
    .split("\n")
    if os.name == "posix"
    # В Windows мы можем использовать команду `Get-NetAdapter`
    # в PowerShell, чтобы получить имя интерфейса по умолчанию.
    # Пример вывода: `Ethernet`, `Wi-Fi` или `Bluetooth Network Connection`.
    else subprocess.check_output(
        "chcp 65001 | powershell.exe -Command \"Get-NetAdapter | where {$_.Status -eq 'Up'} | Select -ExpandProperty Name\"",
        shell=True,
        encoding="utf-8"
    )
    .strip()
    .split("\n")
)

# Это - стандартные пути к исполняемому файлу tshark на разных платформах.
# Они будут переопределены, если вы укажете другой путь к tshark в файле
# `settings.ini` (в поле `CUSTOM_TSHARK_PATH`).
TSHARK_PATH = settings.custom_tshark_path or (
    "tshark" if os.name == "posix" else "C:\\Program Files\\Wireshark\\tshark.exe"
)

# Это - стандартные пути к исполняемому файлу mergecap на разных платформах.
# Они будут переопределены, если вы укажете другой путь к mergecap в файле
# `settings.ini` (в поле `CUSTOM_MERGECAP_PATH`).
MERGECAP_PATH = settings.custom_mergecap_path or (
    "mergecap" if os.name == "posix" else "C:\\Program Files\\Wireshark\\mergecap.exe"
)
