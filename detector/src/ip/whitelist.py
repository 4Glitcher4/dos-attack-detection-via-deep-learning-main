"""Модуль для работы с списком разрешённых IP-адресов."""

from main import settings
from util.logger import log


def add(ip: str):
    """
    Добавляет IP в список разрешённых.

    Аргументы:
        ip (str): IP-адрес, который нужно добавить.

    Возвращает:
        None
    """
    if ip:
        with open(settings.whitelist_path, "a") as f:
            f.write(ip + "\n")
            log.info(f"IP {ip} добавлен в список разрешённых.")


def remove(ip: str):
    """
    Удаляет IP из списка разрешённых.

    Аргументы:
        ip (str): IP-адрес, который нужно удалить.

    Возвращает:
        None
    """
    if ip:
        with open(settings.whitelist_path, "r") as f:
            lines = f.readlines()
        with open(settings.whitelist_path, "w") as f:
            for line in lines:
                if line.strip("\n") != ip:
                    f.write(line)
                if line.strip("\n") == ip:
                    log.info(f"IP {ip} удалён из списка разрешённых.")


def check(ip: str) -> bool:
    """
    Проверяет, есть ли IP в списке разрешённых.

    Аргументы:
        ip (str): IP-адрес, который нужно проверить.

    Возвращает: True, если IP есть в списке разрешённых. Иначе False.
    """
    if ip:
        with open(settings.whitelist_path, "r") as f:
            lines = f.readlines()
        for line in lines:
            if line.strip("\n") == ip:
                return True
    return False
