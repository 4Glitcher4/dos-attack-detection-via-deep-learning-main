"""Это главный модуль, который запускает все остальные процессы."""

import os
import getpass
import asyncio
import requests
import configparser
from os.path import dirname
from os import sep  

from types import SimpleNamespace


# Читаем конфигурацию из файла
_config_parser = configparser.ConfigParser()
_config_parser.read(dirname(dirname(__file__))+sep+"settings.ini", encoding="utf-8")


# Создаем объект с конфигурацией.
# Это позволяет обращаться к конфигурации как к атрибутам объекта.
# Например: `settings.ip_block_threshold`.
settings = SimpleNamespace(
    # Преобразуем все значения в нужный тип, поскольку все значения в
    # конфигурационном файле - строки.
    **{
        key: int(value)  # Если значение - целое число
        if value.isdigit()
        else float(value)  # Если значение - число с плавающей точкой
        if value.replace(".", "", 1).isdigit()
        else value  # Если значение - строка
        for key, value in _config_parser.items("settings")
    }
)

# Получаем абсолютный путь к файлу с белым списком IP-адресов.
settings.whitelist_path = os.path.abspath(settings.whitelist_path)


# Запускаем Telegram-бота.
async def telegram_bot():
    """Запускает бота-уведомителя."""
    import tgbot

    asyncio.ensure_future(tgbot.start_bot())


# Если запускаем из консоли, а не путем импорта
if __name__ == "__main__":
    # Проверяем, указаны ли все необходимые параметры (в том числе, указал ли
    # пользователь свой Telegram ID и токен бота-уведомителя).
    # Если нет, выводим сообщение об ошибке и завершаем работу.
    if (
        settings.your_telegram_id == "123456789"
        or settings.telegram_bot_token
        == "123456789:ABCDEF1234567890ABCDEF1234567890ABC"
    ):
        print(
            "\033[91;1m‼️\tПожалуйста, укажите правильный Telegram ID и токен вашего бота-уведомителя.\033[0m"
        )
        print(
            "\033[91m‼️\tК сожалению, без них мы не сможем отправлять вам уведомления об атаках.\033[0m"
        )
        print(
            "\033[94mℹ\tПодробнее вы можете узнать в файле \033[94;1mREADME.md\033[0m\033[94m, который находится в корневой папке проекта,\033[0m"
        )
        print("\033[94mℹ\tа также в самом файле \033[94;1msettings.ini.\033[0m")
        exit(1)

    # Проверяем, запущен ли API-сервер.
    try:
        response = requests.get(settings.api_url)
    except requests.exceptions.ConnectionError:
        print("\033[91;1m‼️\tНе удалось подключиться к API-серверу.\033[0m")
        print(
            f"\033[91;1m‼️\tПожалуйста, убедитесь, что API-сервер запущен и работает по адресу \033[0m\033[1m{settings.api_url}\033[91;1m.\033[0m"
        )
        exit(1)

    # Если всё в порядке, запускаем процесс сохранения пакетов.
    # Чтобы избежать циклических импортов, импортируем модуль внутри функции.
    import glob
    import tensorflow
    import multiprocessing
    from shutil import which
    import pcap.aio
    import pcap.remover
    import util.const as const
    from util.logger import log

    # Выводим конфигурацию в лог
    for name, value in vars(settings).items():
        log.debug(f"{name} = {value}")

    # Выводим конфигурацию TensorFlow в лог.
    log.debug(f"Версия TensorFlow: {tensorflow.__version__}")
    log.debug(
        f"Список граф. процессоров, используемых Tensorflow: {tensorflow.config.list_physical_devices('GPU')}"
    )
    
    loop = asyncio.get_event_loop()
    loop.run_until_complete(telegram_bot())

    # Удаляем все пакеты, которые могли остаться от предыдущих запусков
    pcap.remover.remove_all_pcaps()

    # Удаляем все результаты анализа, которые могли остаться от предыдущих
    # запусков.
    # Для этого получаем список всех файлов в папке output, которые
    # соответствуют шаблону "predictions-*-*.csv".
    previous_results = glob.glob(
        os.path.join(os.getcwd(), "output", "predictions-*-*.csv")
    )

    # Удаляем все найденные файлы
    for file in previous_results:
        os.remove(file)

    # Выводим в лог количество удаленных результатов анализа
    log.debug(f"Удалено {len(previous_results)} старых результатов анализа.")

    # Проверяем, запущена ли программа от имени пользователя root
    CURRENT_USER = getpass.getuser()
    if os.name == "posix" and CURRENT_USER != "root":
        raise PermissionError(
            "Вы должны запустить программу с правами суперпользователя."
        )

    # Проверяем, установлены ли все необходимые утилиты.
    tshark_path = which(const.TSHARK_PATH)
    mergecap_path = which(const.MERGECAP_PATH)

    # Если утилита не найдена, выводим сообщение об ошибке и завершаем работу.
    if tshark_path is None:
        raise FileNotFoundError("Не найдена утилита tshark.")
    else:
        log.debug(f"Утилита tshark найдена по пути {tshark_path}.")

    # То же самое для mergecap.
    if mergecap_path is None:
        raise FileNotFoundError("Не найдена утилита mergecap.")
    else:
        log.debug(f"Утилита mergecap найдена по пути {mergecap_path}.")

    # Когда мы всё проверили, можно начинать работу.
    proc = multiprocessing.Process(target=pcap.aio.loop, name="tshark")
    proc.start()
    try:
        proc.join()
    except KeyboardInterrupt:
        proc.terminate()
        log.info("Цикл захвата и анализа пакетов прерван пользователем.")
        log.info(
            "Чтобы полностью завершить работу, нажмите клавишу Y и затем Enter, либо нажмите Ctrl+C ещё раз."
            if os.name == "nt"
            else "Выполнение программы завершено."
        )
        proc.join()

        