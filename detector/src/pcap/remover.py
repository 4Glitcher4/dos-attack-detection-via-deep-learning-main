"""Этот модуль содержит функции для удаления файлов захвата."""

import os
from main import settings
from util import const
from util.logger import log


def remove_excess_pcaps(initial_files: list[str], return_mode="removed") -> list[str]:
    """
    Эта функция используется для удаления наиболее старых файлов захвата,
    если их количество больше `config.max_pcap_files`.

    Принимает:
        initial_files (list[str]): Список файлов захвата. Список должен быть
        отсортирован по дате. Наиболее старые файлы должны быть в начале списка.
        Список может содержать либо абсолютные пути, либо относительные пути,
        либо просто имена файлов.
        return_mode (str): Режим возврата. Может принимать значения "removed", "remaining".

    Возвращает:
        Если `return_mode` равен "removed", то возвращает список удалённых файлов.
        Если `return_mode` равен "remaining", то возвращает список оставшихся файлов.

    Пример:
    >>> remove_excess_pcaps(["2021-08-01_00-00-00.pcap", "2021-08-01_00-00-01.pcap"], return_mode="remaining")
    ["2021-08-01_00-00-01.pcap"]
    >>> remove_excess_pcaps(["./2021-08-01_00-00-00.pcap", "./2021-08-01_00-00-01.pcap"], return_mode="removed")
    ["2021-08-01_00-00-00.pcap"]
    """

    # Проверяем, что `return_mode` равен "removed" или "remaining".
    if return_mode not in ["removed", "remaining"]:
        raise ValueError(
            f"Недопустимое значение аргумента `return_mode`: {return_mode}"
        )

    # Записываем в переменную `initial_files` список файлов захвата,
    # которые нужно удалить.
    files_to_remove = initial_files[: -settings.max_pcaps_to_merge]
    removed_files = []

    # Удаляем наиболее старые файлы захвата, если их количество больше нужного.
    # Нам нужно оставить только `config.max_pcap_files` файлов захвата.
    for file in files_to_remove:
        removed_files.append(file)
        os.remove(os.path.join(const.PCAP_DIR, file))

    # Если мы удалили какие-то файлы захвата, выводим сообщение в лог.
    if removed_files:
        log.debug(f"Мы удалили {len(removed_files)} старых файлов захвата.")
        log.debug(f"Старые файлы захвата: {removed_files}")

    # Возвращаем список удалённых или оставшихся файлов захвата.
    return (
        removed_files
        if return_mode == "removed"
        else [item for item in initial_files if item not in removed_files]
    )


def remove_all_pcaps(exceptions: list[str] = [], return_mode="removed") -> list[str]:
    """
    Эта функция используется для удаления всех файлов захвата.

    Используется после того, как мы заблокировали IP-адрес атакующего,
    чтобы после блокировки мы могли проводить анализ новых захваченных пакетов
    без учёта тех, которые были захвачены до его блокировки,
    а также, чтобы не создавать правила-дубликаты в `iptables` или `netsh`.

    Аргументы:
        exceptions (list[str]): Список исключений, которые мы не будем удалять.
        Может содержать либо абсолютные пути, либо относительные пути, либо
        просто имена файлов.
        return_mode (str): Режим возврата. Может принимать значения "removed", "remaining".

    Возвращает:
        Если `return_mode` равен "removed", то возвращает список удалённых файлов.
        Если `return_mode` равен "remaining", то возвращает список оставшихся файлов.

    Вызывает исключения:
        ValueError: Если `return_mode` не равен "removed" или "remaining".

    Пример:
    >>> remove_all_pcaps(["2021-08-01_00-00-00.pcap", "2021-08-01_00-00-01.pcap"])
    ["2021-08-01_00-00-00.pcap", "2021-08-01_00-00-01.pcap"]
    >>> remove_all_pcaps(["/test/data/2021-08-01_00-00-00.pcap", "/test/data/2021-08-01_00-00-01.pcap"], return_mode="remaining")
    []
    >>> remove_all_pcaps(["./2021-08-01_00-00-00.pcap", "./2021-08-01_00-00-01.pcap"], exceptions=["2021-08-01_00-00-00.pcap"])
    ["2021-08-01_00-00-01.pcap"]
    """

    # Проверяем, что `return_mode` равен "removed" или "remaining".
    if return_mode not in ["removed", "remaining"]:
        raise ValueError(
            f"Недопустимое значение аргумента `return_mode`: {return_mode}"
        )

    # Если папка с файлами захвата не существует, выходим из функции.
    if not os.path.exists(const.PCAP_DIR):
        return []

    # На случай, если в `exceptions` переданы не только имена файлов,
    # но и пути к ним, мы удаляем из них путь к папке с файлами захвата.
    exceptions = [os.path.basename(item) for item in exceptions]

    # Здесь мы будем хранить количество удалённых файлов захвата, и пути к ним,
    # чтобы мы могли их вывести в лог.
    initial_files = os.listdir(const.PCAP_DIR)
    removed_files = []

    # Удаляем все файлы захвата, кроме тех, что указаны в списке исключений.
    for pcap_file in initial_files:
        if not os.path.basename(pcap_file) in exceptions:
            removed_files.append(pcap_file)
            os.remove(os.path.join(const.PCAP_DIR, pcap_file))

    # Выводим сообщение в лог.
    if removed_files:
        log.debug(f"Мы удалили {len(removed_files)} файлов захвата.")
        log.debug(f"Удалённые файлы захвата: {removed_files}")

    # Возвращаем список удалённых или оставшихся файлов захвата.
    return (
        removed_files
        if return_mode == "removed"
        else [item for item in initial_files if item not in removed_files]
    )
