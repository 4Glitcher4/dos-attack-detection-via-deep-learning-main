"""Этот модуль содержит функцию `block`, которая блокирует IP-адрес с помощью
`netsh` на Windows или `iptables` на Linux."""

import os
import subprocess
from util.logger import log


def block(ip: str) -> bool:
    """
    Блокирует IP-адрес с помощью `netsh` на Windows или `iptables` на Linux.

    Требует административных прав (root на Linux или администратор на Windows).

    Аргументы:
        ip (str): IP-адрес, который нужно заблокировать.

    Возвращает:
        True, если блокировка прошла успешно, иначе False.

    Пример:
    >>> block("123.45.67.8")
    True
    """

    # Импортируем модуль `remover`, чтобы удалять старые файлы захвата,
    # когда мы блокируем IP-адрес атакующего.
    # Впоследствии мы будем проводить анализ захваченных пакетов без
    # учёта тех, которые были захвачены до блокировки IP-адреса.
    # Таким образом, мы не будем создавать лишние правила-дубликаты
    # в `iptables` или `netsh`.
    import pcap.remover as remover

    # Если мы работаем на Linux, то нам нужно использовать `iptables`.
    # Если мы работаем на Windows, то нам нужно использовать `netsh`.
    COMMAND = (
        [
            "iptables",
            "-A",
            "INPUT",
            "-s",
            ip,
            "-j",
            "DROP",
        ]
        if os.name == "posix"
        else [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name=Block {ip}",
            "dir=in",
            "action=block",
            f"remoteip={ip}",
            "enable=yes",
        ]
    )

    # Запускаем команду.
    process = subprocess.run(
        COMMAND,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        encoding="utf-8",
    )

    # Ждём завершения процесса.
    if process.returncode == 0:
        log.info(f"\033[1mМы заблокировали {ip} с помощью {COMMAND[0]}.\033[0m")

        # Удаляем старые файлы захвата, чтобы не создавать правила-дубликаты
        # в `iptables` или `netsh` после того, как мы будем проводить анализ
        # новых захваченных пакетов после блокировки.
        remover.remove_all_pcaps()
        return True
    else:
        log.warn(
            f"\033[1mМы не смогли заблокировать {ip} с помощью {COMMAND[0]}.\033[0m"
        )
        return False
