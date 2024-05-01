Чтобы создать контейнер с приложением, необходимо выполнить команду:
```bash
docker build -t dos-attack-detection-diploma .
```

Чтобы запустить контейнер с приложением, необходимо выполнить команду:
```bash
docker run --rm -it --cap-add=NET_RAW --cap-add=NET_ADMIN dos-attack-detection-diploma
```
