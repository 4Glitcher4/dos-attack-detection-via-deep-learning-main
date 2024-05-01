"""Это вспомогательный модуль, который используется для объединения файлов
захвата."""

import os
import subprocess
import pcap.remover as remover
import util.const as const
from main import settings
from util.logger import log


def merge_capture_files() -> str:
    """
    Эта функция используется для объединения в один файл всех ранее сохранённых
    PCAP-файлов (файлов захвата), которые начинаются с `const.PCAP_FILENAME`,
    и находятся в `const.PCAP_DIR`.

    Не принимает никаких аргументов.

    Возвращает:
        Путь к объединённому PCAP-файлу.

    Пример:
    >>> merge_capture_files()
    "/tmp/lucid/merged.pcap"
    """

    # Получаем список всех файлов захвата в указанном каталоге
    capture_files = [
        f for f in os.listdir(const.PCAP_DIR) if f.startswith(const.PCAP_FILENAME)
    ]

    # К счастью, мы добавляем время в название файла захвата, поэтому мы можем
    # просто отсортировать список файлов захвата по алфавиту и получить тот же
    # эффект, что и от сортировки по времени.
    capture_files.sort()

    # Удаляем лишние файлы захвата, если они есть, так, чтобы оставалось
    # только `config.max_pcap_files` файлов захвата (по умолчанию - 7).
    capture_files = remover.remove_excess_pcaps(capture_files, return_mode="remaining")

    # Устанавливаем путь к объединённому файлу захвата.
    merged_file_path = os.path.join(
        const.PCAP_DIR, f"{const.MERGED_PCAP_FILENAME}.pcap"
    )

    # Вызываем команду `mergecap` на соединённом файле захвата через подпроцесс.
    subprocess.check_call(
        [
            # Мы получаем `PermissionError: [WinError 5] Access Denied`, если
            # просто вызываем `mergecap.exe` на Windows.
            # Не знаю почему, но этот костыль c `conhost.exe` работает.
            # К сожалению, мы увидим появляющиеся командные строки при
            # объединении, но так пока что сойдёт.
            # Программирование на Windows - сплошное веселье.
            # TODO: Разобраться почему это происходит, и переписать это.
            # Возможно, от имени администратора mergecap заработает, но это
            # не точно.
            const.MERGECAP_PATH,
            "-w",
            merged_file_path,
        ]
        + [os.path.join(const.PCAP_DIR, f) for f in capture_files],
    )

    # Если файл был успешно создан, возвращаем путь к нему.
    if os.path.exists(merged_file_path):
        log.debug(
            f"Мы объединили новый файл с предыдущими и сохранили его по пути {merged_file_path}."
        )
        log.debug(f"Предыдущие файлы: {capture_files}")
        return merged_file_path

    # Если выполнить команду `mergecap` не удалось, вызываем исключение.
    else:
        raise RuntimeError(
            f"Не удалось объединить файлы захвата. Возможно, доступ к {const.MERGECAP_PATH} был запрещён?"
        )
