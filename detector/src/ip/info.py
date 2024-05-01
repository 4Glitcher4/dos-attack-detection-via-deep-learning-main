"""Этот модуль содержит функции для получения информации об IP-адресе."""

import requests


def get_readable(ip: str, filter_keys: list[str] = [], readable=True) -> str:
    """
    Получает информацию об IP-адресе отправителя, используя
    сервис `ipinfo.io`, и возвращает её в читаемом виде.

    Аргументы:
        ip (str): IP-адрес отправителя.
        filter_keys (list[str]): Список ключей, которые нужно исключить из
        возвращаемой информации.

    Возвращает:
        str: Информация об IP-адресе отправителя в читаемом виде.

    Пример:
    >>> readable_info("192.168.1.1")
    'IP: 192.168.1.1\\nЛокальный IP-адрес: True'
    >>> readable_info("8.8.8.8", filter_keys=["ip", "readme"])
    'Организация: AS15169 Google LLC\\nСтрана: US\\nРегион: California\\nГород: Mountain View\\nКоординаты: 37.4056,-122.0775\\nПровайдер: dns.google\\nПочтовый индекс: 94043\\nЧасовой пояс: America/Los_Angeles'
    """

    # Берём информацию об IP-адресе отправителя, используя
    # сервис ipinfo.io.
    ip_info = requests.get(f"http://ipinfo.io/{ip}").json()

    # Если readable=False, то возвращаем информацию в виде словаря,
    # ровно так, как она возвращается сервисом ipinfo.io.
    if not readable:
        return ip_info

    # Если readable=True, то возвращаем информацию в читаемом виде.

    # Создаём словарь, в котором ключ - это название поля,
    # которое возращает сервис ipinfo.io, а значение - это
    # название поля, которое мы хотим получить в читаемом виде.
    readable_strings = {
        "ip": "IP",
        "org": "Организация",
        "country": "Страна",
        "anycast": "Используется метод Anycast",
        "region": "Регион",
        "city": "Город",
        "loc": "Координаты",
        "hostname": "Провайдер",
        "postal": "Почтовый индекс",
        "timezone": "Часовой пояс",
        "bogon": "Локальный IP-адрес",
        "hostname": "Провайдер",
        "readme": "Ссылка на документацию",
    }

    # Возвращаем информацию в читаемом виде, исключая ключи, заданные
    # в аргументе filter_keys.
    return "\n".join(
        f"{readable_strings[key]}: {ip_info[key]}"
        for key in readable_strings.keys()
        if key in ip_info and key not in filter_keys
    )
