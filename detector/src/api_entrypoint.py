import os
import json
import subprocess
from collections import Counter
from sys import argv
from util import const

def get_most_frequent_sender(pcap_file: str, sender_count: str):
    """
    Получает IP-адрес отправителя, который отправил больше всего пакетов.

    Запускает процесс `tshark` для анализа PCAP-файла (файла захвата),
    затем разделяет всё, чтобы получить только IP-адрес отправителя.
    Затем он ищет наиболее часто встречающийся IP-адрес отправителя,
    который не является нашим локальным (например, если мы были отправителем).

    Скорее всего, это не самый эффективный способ, но он работает.

    Аргументы:
        pcap_file (str): Путь к PCAP-файлу.

    Возвращает:
        Самый часто встречающийся IP-адрес отправителя, который не является
        нашим собственным.

    Пример:
    >>> get_most_frequent_sender("tests/test_data/pcap_files/merged.pcap")
    "123.45.67.89"
    """
    pcap_file = argv[1]
    sender_count = argv[2]
    # Получаем локальный IP-адрес текущей машины.
    # hostname -I может выдать несколько IP-адресов.
    current_local_ips = (
        subprocess.check_output("hostname -I", shell=True).decode("utf-8").strip()
        if os.name == "posix"
        else subprocess.check_output("ipconfig | findstr IPv4", shell=True)
        .decode("utf-8")
        .split(":")[1]
        .strip()
    )

    # Если нам выдали несколько IP-адресов, разделим их по пробелам.
    # Если мы получили только один IP-адрес, он будет просто обёрнут в список.
    current_local_ips = current_local_ips.split()
    
    # Запускаем `tshark -r <файл>` для анализа PCAP-файла.
    # Выходные данные обычно имеют следующий вид:
    # 1038 7.740723639 192.168.1.201 → 192.168.1.177 TCP 66 443 → 45892 [ACK] Seq=686 Ack=346 Win=83 Len=0 TSval=1795305211 TSecr=88283636
    # Подробнее: https://www.redhat.com/sysadmin/using-wireshark-tshark1
    tshark_output = subprocess.check_output(
        [
            const.TSHARK_PATH,
            "-r",
            pcap_file,
        ],
        stdin=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Разделяем выходные данные по строкам.
    tshark_output = tshark_output.decode("utf-8")
    lines = tshark_output.strip().split("\n")

    # Мы создаем список IP-адресов отправителей, исключая наш локальный IP-адрес
    # (или IP-адреса, если мы получили несколько).
    # Мы будем использовать это для нахождения наиболее часто встречающегося
    # IP-адреса.
    # Не самое эффективное решение, но оно работает.
    senders = [
        # Нам нужно получить IP-адрес отправителя из каждой строки.
        # Это третий (индекс = 2, так как мы начинаем с 0) элемент в строке,
        # поэтому мы разделим строку по пробелам и получим элемент по индексу 2.
        line.split()[2]
        for line in lines
        if line.split()[2] not in current_local_ips
    ]

    # Наиболее часто встречающийся IP-адреса отправителей.
    most_frequent_senders = []

    for sender in Counter(senders).most_common(int(sender_count)):
        most_frequent_senders.append({"IpAddress" : sender[0], "RequestCount": sender[1]})

    json_data = json.dumps(most_frequent_senders) # Преобразование списка в JSON
    print(json_data)


get_most_frequent_sender()