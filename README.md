# Обнаружение DoS-атак с помощью решений машинного обучения.

Обнаружение DoS-атак с помощью https://github.com/doriguzzi/lucid-ddos.

# Как использовать:

## Linux:

**0. Если вы ещё не включили ваш веб-сервер, включите его.**

Чтобы сделать это, введите в терминал:

```
uvicorn server:app --reload --host 0.0.0.0 --port 8787
```

**1. Скачайте этот репозиторий и перейдите во внутреннюю папку:**

Откройте терминал в меню приложений и введите:

```
git clone https://github.com/nmatveev-gosu/dos-attack-detection-via-deep-learning
cd dos-attack-detection-via-deep-learning/
```

Вы также можете скачать этот репозиторий ZIP-архивом, и открыть его в вашем
менеджере файлов, а из него уже запустить терминал.

**2. Установите зависимости (`libpcap`, `libwsutil11`, `libwireshark13`, а также `wireshark-common` и `tshark` версий ниже или равных 3.2.13):**

_(для этого потребуются права суперпользователя!)_

Нужные пакеты уже имеются в репозитории. Они хранятся в папке `deps`.

Введите в терминал следующее, чтобы их установить.

```
sudo apt install ./deps/deb/*
```

При установке `tshark` появится окно по типу такого _(в вашем случае красным будет выделено `No`):_
![image](https://user-images.githubusercontent.com/127086308/229115677-5aa41393-a72f-4836-9202-be373a4c9493.png)

Здесь стрелкой влево выберите `Yes`. Нажмите `Enter`.

Без этого программа может столкнуться с проблемой ловли пакетов, если она
запущена без прав суперпользователя (с командой `sudo` перед исполняемым
файлом).

> **Обратите внимание!**
>
> Скорее всего, вам потребуется также добавить правило, предотвращающее обновление
> этих пакетов, поскольку LUCID не был протестирован на версиях `tshark` выше
> 3.2.13, и были замечены баги _(см. [https://github.com/doriguzzi/lucid-ddos#installation](https://github.com/doriguzzi/lucid-ddos#installation:~:text=Please%20note%20that%20the%20current%20LUCID%20code%20works%20with%20tshark%20version%203.2.13%20or%20lower.%20Issues%20have%20been%20reported%20when%20using%20newer%20releases%20such%20as%203.4.X.))_.
>
> Чтобы сделать это, введите в терминал:
>
> ```
> sudo apt-mark hold libpcap0.8 libwiretap10 libwireshark13 libwsutil11 libwireshark13 wireshark-common tshark
> ```

**3. Отредактируйте файл конфигурации `settings.ini`**

В этом примере мы используем консольный редактор `nano`.
Вы можете использовать консольный редактор `vi`, графический редактор `gedit`,
либо любой другой редактор, доступный в вашей системе.

`nano` по умолчанию встроен в большинство систем.

```
nano ./settings.ini
```

Вы сможете найти внутри файла текст примерно такого содержания:

```ini
# Здесь вам нужно указать ваш Telegram ID.
# Вы можете узнать ваш ID, написав боту `@getmyid_bot`.
YOUR_TELEGRAM_ID=123456789
```

Здесь измените значение `YOUR_TELEGRAM_ID` _(то, что находится после знака `=`)_
с `123456789` ваш Telegram ID. Вы можете узнать его, используя бота
[@getmyid_bot](https://t.me/@getmyid_bot).

Это требуется, чтобы оповещать вас о новых атаках.
Если вы не измените значение `YOUR_TELEGRAM_ID`, мы не сможем отправлять вам
сообщения, а программа не заработает.

Также вы можете использовать другого бота для уведомлений.
Для этого просто смените значение `TELEGRAM_BOT_TOKEN`.

После того, как вы внесли изменения, нажмите `Ctrl+S`, чтобы выйти - `Ctrl+X`, чтобы сохранить их.

**4. Скачайте Miniconda3.**

Скачайте самую новую версию Miniconda3, дайте установщику право на
исполнение, и запустите его. Для этого введите:

```
curl -LO https://repo.anaconda.com/miniconda/Miniconda3-py39_23.1.0-1-Linux-x86_64.sh
chmod +x ./Miniconda3-py39_23.1.0-1-Linux-x86_64.sh
./Miniconda3-py39_23.1.0-1-Linux-x86_64.sh -b
```

Ключ `-b` (англ. "batch") указывает установщику, что нужно установить
Miniconda3 в домашнюю директорию текущего пользователя, с настройками по
умолчанию и без показа лицензионного соглашения.

Далее, чтобы можно было запускать Miniconda3 из любой директории, введите:

```
conda init bash
source ~/.bashrc
```

**5. Настройте разрешения на запуск системных файлов.**

`tshark` на Linux захватывает данные с помощью встроенной системной утилиты
`dumpcap`. К сожалению, по умолчанию запускать её можно исключительно с
правами суперпользователя. Мы хотим запускать её от текущего пользователя,
поэтому должны ввести в терминал следующую команду:

```
sudo chmod +x /usr/bin/dumpcap
```

**6. Создайте и откройте новую виртуальную среду Python для Conda.**

В нашем случае лучшим вариантом будет создать новую виртуальную среду
в папке `.env` внутри папки проекта.

Для этого введите в терминал:

```
conda create --prefix ./env python=3.9
conda activate ./env
```

**7. Запустите проект:**

Введите в терминал:

```
./run.sh
```

Скорее всего, вам предложат создать новое виртуальное окружение. Введите `y` и
нажмите `Enter`.

Остальное (в том числе, определение текущего IP и используемого Ethernet- или
Wi-Fi-интерфейса) будет выполнено автоматически.

**8. Наслаждайтесь!**

Теперь проект запущен.

Чтобы посмотреть все выводы модели LUCID за время выполнения программы, введите
в новом окне или новой вкладке терминала:

```
tail ./output/* | column -t -s ','
```

_(для просмотра вы должны находиться в папке проекта - там, где вы сохранили
репозиторий)_

Чтобы прекратить выполнение программы, просто нажмите `Ctrl+C`, и вы вернётесь в
окно терминала.

**9. Если случаются ошибки:**

Попробуйте связаться со мной в Telegram: [https://t.me/fiftyfrog](https://t.me/fiftyfrog)

## Windows:

**1. Отредактируйте файл run.bat**

Если вы установили Anaconda/Miniconda в другую папку во время установки,
смените