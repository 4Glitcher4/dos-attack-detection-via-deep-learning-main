"""Это вспомогательный модуль, который используется для запуска модели LUCID."""

import os
import csv
import time
import subprocess
import multiprocessing
from util import const
from util.logger import log
from main import settings


def run_predict_live_subprocess(path_to_pcap: str):
    """
    Запускает модель LUCID в подпроцессе.
    Обычно вызывается функцией `cnn.ask()`.

    Сохраняет вывод модели в CSV-файл, по пути
    `<текущая_папка>/output/predictions-<дата>-<время>.csv`

    Например:
    `/home/user/dos-attack-detection-via-deep-learning/output/predictions-20230401-223019.csv`

    Команда, которая запускается под капотом, выглядит так:
    `python lucid_cnn.py --predict_live <path_to_pcap> --model <path_to_model> --dataset_type DOS2019`.
    Пожалуйста, обратите внимание, что вывод консоли перенаправляется в
    `/dev/null`.


    Аргументы:
        path_to_pcap (str): Путь к PCAP-файлу, который нужно анализировать.

    Возвращает:
        None

    Пример:
    >>> run_predict_live_subprocess("/home/user/pcaps/merged.pcap")
    """
    process = subprocess.Popen(
        [
            "..\.venv\Scripts\python.exe",
            os.path.join(const.LUCID_DIR, "lucid_cnn.py"),
            "--predict_live",
            path_to_pcap,
            "--model",
            os.path.join(const.LUCID_MODEL_DIR, "10t-10n-DOS2019-LUCID.h5"),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    print("stdout: " + process.stdout.read().decode('utf-8'))
    print("stderr: " + process.stderr.read().decode('utf-8'))


def ask(path_to_pcap: str) -> list[dict[str, str]]:
    """
    Просит модель LUCID, чтобы она анализировала PCAP-файл.
    Затем ожидает, пока модель закончит и сохранит файл.
    Файл затем читается, и результаты возвращаются в виде списка словарей.
    Если модель не смогла сгенерировать выходные данные за
    `config.lucid_analyze_timeout` (секунд), то возвращается пустой список.

    Максимальное время ожидания можно изменить в файле `settings.ini`, в пункте
    `LUCID_ANALYZE_TIMEOUT`.

    Аргументы:
        path_to_pcap (str): Путь к PCAP-файлу, который нужно анализировать.

    Возвращает:
        Список словарей, где каждый словарь представляет собой строку в
        CSV-файле. Может быть пустым, если модель не смогла или не успела
        сгенерировать выходные данные.

    >>> ask("/home/user/pcaps/merged.pcap")
    [{'Model': 'DOS2019-LUCID', 'Time': '0.112', 'Packets': '110', 'Samples': '20', 'DDOS%': '0.200', 'Accuracy': 'N/A', 'F1Score': 'N/A', 'TPR': 'N/A', 'FPR': 'N/A', 'TNR': 'N/A', 'FNR': 'N/A', 'Source': 'merged.pcap'}]
    """
    log.debug(f"Просим модель проанализировать {path_to_pcap}.")

    # Прежде чем создавать какие-либо новые файлы, убедимся,
    # что папка `output` существует.
    os.makedirs(const.CSV_OUTPUT_DIR, exist_ok=True)

    # Запускаем процесс свёрточной нейронной модели.
    # Нам нужно это делать в отдельном подпроцессе, поскольку любой ввод и
    # вывод в таком случае были бы заблокированы, пока модель не закончит анализ.
    cnn_proc = multiprocessing.Process(
        target=run_predict_live_subprocess, args=(path_to_pcap,)
    )
    cnn_proc.name = "Предсказание модели LUCID"
    cnn_proc.start()
    log.debug(
        f"Запущен процесс {cnn_proc.name}. Идентификатор процесса: {cnn_proc.pid}."
    )

    # Запоминаем список файлов в папке `output` до того, как мы запустили модель.
    initial_files = os.listdir(const.CSV_OUTPUT_DIR)
    while True:
        # Проверяем, появился ли новый файл в папке `output`.
        current_files = os.listdir(const.CSV_OUTPUT_DIR)
        new_files = set(current_files) - set(initial_files)
        if new_files:
            # Сохраняем текущее время. Если мы будем ждать выходные данные
            # модели более 5 секунд после того, как будет создан CSV-файл,
            # то мы должны убить процесс.
            current_timestamp = int(time.time())

            # Пишем в лог, что модель создала новый файл.
            log.debug(
                "Модель создала CSV-файл, но, вероятно, он пуст (или содержит только заголовки - имена столбцов)."
            )

            # Получаем только что созданный файл.
            (new_file,) = new_files
            newfile_path = os.path.join(const.CSV_OUTPUT_DIR, new_file)

            # Пишем пользователю, что мы ждём, пока модель сгенерирует
            # выходные данные в полном объёме.
            log.debug(
                f"Пожалуйста, подождите, пока {newfile_path} не будет 2 строки или длиннее..."
            )

            # LUCID сначала создаёт файл, а затем дополняет его.
            # Это прописано в исходном коде `lucid_cnn.py`.
            # Проверяем каждые 0,1 секунды, если файл состоит из 2 строк или более.
            while True:
                with open(newfile_path, "r") as file:
                    line_count = sum(1 for _ in file)
                if line_count > 1:
                    log.debug(
                        "Модель дополнила CSV-файл. Теперь он содержит 2 строки или более. Мы можем продолжить работу."
                    )

                    # Завершаем подпроцесс, поскольку мы получили ответ.
                    cnn_proc.kill()

                    # Читаем CSV-файл и возвращаем его содержимое.
                    # Обычно содержимое сгенерированного CSV-файла состоит
                    # всего из одной записи, но кто знает...
                    with open(newfile_path, "r") as file:
                        reader = csv.DictReader(file)
                        rows = list(reader)

                        # Переводим проценты в человекочитаемый формат.
                        ddos_probability_pretty = (
                            f"{round(float(rows[0]['DDOS%']), 2) * 100}%"
                        )

                        # Если количество пакетов в файле меньше минимального
                        # количества пакетов, которое должна содержать
                        # сетевая атака, то мы не можем вынести вердикт, и
                        # не можем доверять результатам модели.
                        if int(rows[0]["Packets"]) < settings.min_packets_count:
                            log.info(
                                f"\033[1mКоличество пакетов в файле ({rows[0]['Packets']}) меньше допустимого ({settings.min_packets_count}). Модель LUCID не может вынести верный вердикт\033[0m."
                            )
                        # Если количество пакетов в файле больше или равно
                        # минимальному допустимому количеству пакетов...
                        else:
                            # Если вероятность DDoS больше порогового значения, то
                            # бьём тревогу, и пытаемся заблокировать IP-адрес отправителя.
                            if float(rows[0]["DDOS%"]) > settings.ip_block_threshold:
                                log.info(
                                    f"\033[93;1mВы в опасности! Вероятность DDOS равна: {ddos_probability_pretty} (выше чем {settings.ip_block_threshold*100}%)! Вердикт вынесен по {rows[0]['Packets']} пакетам.\033[0m"
                                )
                                return rows

                            # Выводим результаты в консоль, а также возращаем как
                            # результат функции.
                            log.info(
                                f"\033[1mВы в безопасности. Вероятность DDoS равна: {ddos_probability_pretty}, вердикт вынесен по {rows[0]['Packets']} пакетам.\033[0m"
                            )
                        return rows

                # Если модель слишком долго генерирует выходные данные,
                # то завершаем её подпроцесс, и возвращаем пустой список.
                if (
                    int(time.time()) - current_timestamp
                    > settings.lucid_analyze_timeout
                ):
                    log.info(
                        f"Модель слишком долго генерирует выходные данные (прошло уже {int(time.time()) - current_timestamp} из положенных {settings.lucid_analyze_timeout}). Завершаем процесс..."
                    )
                    cnn_proc.kill()
                    log.info("Мы завершили процесс модели LUCID.")
                    return []

                # Ожидаем 0,1 секунды, чтобы не перегружать процессор.
                time.sleep(0.1)
