"""Это - модуль, используемый для захвата пакетов с сетевого
интерфейса."""

import json
import os
import neural
import asyncio
import pyshark
import requests
import util.const as const
from . import remover
from util.logger import log
from datetime import datetime


def loop():
    """
    Бесконечный цикл, который захватывает пакеты с сетевого интерфейса,
    и передаёт их в `neural.cnn.ask()` для анализа.

    Создает временный каталог по пути `/tmp/lucid`
    (или `C:\\Users\\%USERNAME%\\AppData\\Local\\Temp\\lucid` в Windows),
    запускает бесконечный цикл, который захватывает пакеты из сетевого
    интерфейса (указанного в константе `util.const.LUCID_INTERFACE`).

    `pyshark.LiveCapture` ловит пакеты и сохраняет их в PCAP-файлы в этом
    временном каталоге.

    К сожалению, новые PCAP-файлы не объединяются с предыдущими, поэтому
    мы должны объединять их вручную, используя функцию
    `pcap.merger.merge_capture_files()`.

    Путь к этому объединенному файлу затем передается другой функции с именем
    `neural.cnn.ask()`, которая обрабатывает файл и возвращает результат.

    Не принимает никаких аргументов.

    Эта процедура никогда не возвращает результат и выполняется бесконечно
    (обычно в фоновом подпроцессе), пока не будет остановлена вручную.

    Вызывает исключения:
        TSharkNotFoundException: В случае, если исполняемый файл `tshark` не найден.
        (вызывается в модуле `pyshark`)
    """

    # Если каталог `PCAP_DIR` не существует, создаём его.
    if not os.path.exists(const.PCAP_DIR):
        os.makedirs(const.PCAP_DIR)
        log.debug(
            f"Директория {const.PCAP_DIR} успешно создана! Мы будем сохранять PCAP-файлы здесь."
        )
    else:
        log.debug(f"{const.PCAP_DIR} уже существует, сохраняем PCAP-файлы здесь.")

    # Чтобы избежать циклических импортов, импортируем модули внутри функции.
    import tgbot
    import pcap.merger as merger
    import pcap.analyzer as analyzer
    from main import settings

    # Эта переменная используется для того, чтобы удалять старые файлы
    should_remove = False

    # Начинаем бесконечный цикл.
    while True:
        try:
            log.debug("Начинаем захват пакетов...")

            # Создаем экземпляр pyshark.LiveCapture с интерфейсом и выходным файлом.
            capture = pyshark.LiveCapture(
                interface=const.LUCID_INTERFACES,
                output_file=os.path.join(
                    const.PCAP_DIR,
                    f"{const.PCAP_FILENAME}_{datetime.now().strftime('%d%m%Y_%H%M%S_%f')}.pcap",
                ),
            )
            log.debug(f"Захватчик пакетов на интерфейсах {capture.interfaces} создан.")

            # Начинаем захват пакетов.
            for _ in capture.sniff_continuously(packet_count=1):
                # Если мы захватили достаточно пакетов, удаляем старые файлы
                # за все предыдущие захваты.
                if should_remove:
                    remover.remove_all_pcaps(exceptions=[capture._output_file])  # type: ignore
                    should_remove = False

                log.debug(f"Сохранён файл: {capture._output_file}")

                # Соединяем каждый новый PCAP-файл с предыдущими.
                # Это необходимо, потому что pyshark.LiveCapture не объединяет файлы
                # сам по себе.
                path_to_merged_file = merger.merge_capture_files()

                # Передаём объединённый файл в LUCID-модель.
                # Нам нужно значение "DDOS%", а также "Packets", чтобы
                # определить, достаточно ли пакетов для анализа.
                try:
                    cnn_result = neural.ask(path_to_merged_file)
                except KeyboardInterrupt:
                    log.info("Процесс анализа прерван пользователем.")

                # Если модель не вернула результат, пропускаем этот файл.
                if "cnn_result" not in locals() or not cnn_result:  # type: ignore
                    continue

                # Если вероятность DDOS больше порогового значения, а также
                # количество пакетов больше минимально допустимого (результатам
                # анализа можно доверять только при достаточном количестве пакетов),
                # бьём тревогу, и сообщаем об этом пользователю в Telegram.
                if int(cnn_result[0]["Packets"]) > settings.min_packets_count:
                    # Берём IP-адрес отправителя, отправившего наибольшее
                    # количество пакетов и решаем, что это - атакующий.
                    # TODO: Сделать это более умным способом.
                    # Было бы круто использовать отдельную нейронку для этого...
                    analyzer.save_most_frequent_sender(path_to_merged_file)
                    with open(const.MOST_FREQUENT_SENDER_FILE_PATH, "r") as f:
                        # Строка может содержать пробелы/символы новой строки,
                        # поэтому мы должны использовать strip().
                        most_frequent_sender = json.loads(f.readline().strip())

                        # Сохраняем результаты в базу данных.
                        requests.post(
                            f"{settings.api_url}/api/logs/",
                            json={
                                "ip": most_frequent_sender[0],
                                "created_at": str(datetime.utcnow().isoformat() + "Z"),
                                "ddos_probability": float(cnn_result[0]["DDOS%"]),
                                "request_count": most_frequent_sender[1]
                            },
                        )

                        # Если строка, содержащая наиболее частого отправителя,
                        # не пуста (или не является просто пробелом), отправляем
                        # сообщение в Telegram.
                        if (
                            float(cnn_result[0]["DDOS%"]) > settings.ip_block_threshold
                            and most_frequent_sender != ""
                        ):
                            # Отправляем сообщение в Telegram, с запросом
                            # на блокировку IP-адреса.
                            asyncio.get_event_loop().run_until_complete(
                                tgbot.send_ddos_notification(most_frequent_sender[0])
                            )

                    # После того, как мы отправили сообщение в Telegram, нужно
                    # удалить все файлы, которые были созданы в процессе анализа.
                    # Это нужно, чтобы не анализировать их снова, если
                    # пользователь решит заблокировать IP-адрес.
                    # Мы удалим их при следующем проходе цикла, потому что
                    # сейчас Pyshark ещё не закончил запись в файл.
                    should_remove = True

        # Если пользователь прервал процесс захвата пакетов, прерываем цикл.
        except (KeyboardInterrupt, EOFError, SystemExit):
            log.info("Захват пакетов прерван пользователем.")
            break
