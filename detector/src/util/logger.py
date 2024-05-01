"""Здесь создаётся логгер, который будет использоваться во всем проекте."""

import logging
from main import settings

# Создаем экземпляр логгера
log = logging.getLogger(__name__)
log.propagate = False

# Преобразуем строку с уровнем логгирования в число, понятное логгеру
if settings.logging_level == "CRITICAL":
    _level = 50
elif settings.logging_level == "ERROR":
    _level = 40
elif settings.logging_level == "WARNING":
    _level = 30
elif settings.logging_level == "INFO":
    _level = 20
elif settings.logging_level == "DEBUG":
    _level = 10
else:
    _level = 0

# Задаем уровень логгирования
log.setLevel(_level)

# Создаем обработчик логов
handler = logging.StreamHandler()
handler.setFormatter(
    logging.Formatter(
        "[90m%(asctime)s[0m %(levelname)s[90m - [%(filename)s:%(lineno)d][0m %(message)s"
    )
)
log.addHandler(handler)
