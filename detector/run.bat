@echo off

rem Разрешаем изменение переменных во время выполнения циклов.
setlocal EnableDelayedExpansion

rem Устанавливаем UTF-8 кодировку для совместимости со старыми версиями Windows.
chcp 65001 >nul

set "CONDA_LOCATION=C:\Users\%USERNAME%\miniconda3\Scripts\activate.bat"

for /f %%i in ("%~dp0.") do set "SCRIPT_DIR=%%~si"

set "VENV_DIR=.venv"
set "ENV_PREFIX=%SCRIPT_DIR%\%VENV_DIR%"

rem Проверяем права администратора.
if "%PROCESSOR_ARCHITECTURE%" equ "amd64" (
  >nul 2>&1 "%SYSTEMROOT%\SysWOW64\cacls.exe" "%SYSTEMROOT%\SysWOW64\config\system"
) else (
  >nul 2>&1 "%SYSTEMROOT%\System32\cacls.exe" "%SYSTEMROOT%\System32\config\system"
)

rem Если флаг ошибки установлен, у нас нет администратора.
if "%ERRORLEVEL%" neq "0" (
  echo Запрашиваем права администратора...
  goto UACPrompt
) else (
  echo Права администратора получены. Продолжаем...
  goto gotAdmin
)

rem Предлагаем повысить привилегии.
:UACPrompt
  echo Set UAC = CreateObject^("Shell.Application"^) > "%TEMP%\getadmin.vbs"
  set params= %*
  echo UAC.ShellExecute "cmd.exe", "/c ""%~s0"" %params:"=""%", "", "runas", 1 >> "%temp%\getadmin.vbs"

  "%TEMP%\getadmin.vbs"
  del "%TEMP%\getadmin.vbs"
  exit /b

rem Администратор получен, продолжаем выполнение скрипта.
:gotAdmin
  pushd "%CD%"
  cd /d "%~dp0"

rem Уведомляем пользователя, что мы запускаем скрипт.
echo Чтобы выйти из программы, нажмите [1mCtrl+C[0m, а затем [1mY[0m.

rem Пытаемся активировать Conda и выходим из скрипта, если его не удалось
rem активировать. В противном случае выводим сообщение и продолжаем.
echo Проверяем, установлена ли Conda.
call "%CONDA_LOCATION%"
if %ERRORLEVEL% neq 0 (
  echo Ой. Мы не можем найти Conda на вашем ПК.
  echo Чтобы запустить этот сценарий, вам нужно установить Miniconda или Anaconda.
  echo Вы можете скачать установщик для Windows здесь: [94;1mhttps://repo.anaconda.com/miniconda/Miniconda3-py39_23.1.0-1-Windows-x86_64.exe[0m
  echo Если вы уже установили Conda, убедитесь, что путь к `activate.bat` в `run.bat` указан правильно.
  echo Ожидаем 5 секунд, а затем выходим... ^(нажмите Ctrl+C и Y, чтобы закрыть сразу^)
  timeout /t 5 >nul
  exit /b 1
)
echo Мы нашли Conda.

rem Проверяем, активировано ли виртуальное окружение Conda 'python39'.
set CONDA_DEFAULT_ENV=%CONDA_DEFAULT_ENV:"=%
if "%CONDA_DEFAULT_ENV%"=="%ENV_PREFIX%" (
  rem Активируем виртуальное окружение 'python39' и устанавливаем все зависимости
  echo Виртуальное окружение для Conda в папке '%ENV_PREFIX%' уже было активировано. Устанавливаем все необходимое...
) else (
  rem Если 'python39' Conda окружение не активировано:
  rem Проверяем, существует ли 'python39' Conda окружение или нет
  call conda env list | findstr /i /c:%SCRIPT_DIR% | findstr /i /c:%VENV_DIR% >nul
  if !ERRORLEVEL! equ 0 (
    call :activateEnv
  ) else (
    call :promptToCreateNewEnv
  )
)

rem Если виртуальное окружение не активировано, выходим из скрипта.
if %ERRORLEVEL% neq 0 (
  exit /b 1
)

rem Печатаем версии Conda и Python.
echo Версия Conda:
call conda -V
echo Версия Python:
call python --version
echo Текущая виртуальная среда:
echo %CONDA_DEFAULT_ENV%

rem Пробуем найти pip. Если не удается, пытаемся установить его.
rem Скрываем сообщения об уже установленных зависимостях, чтобы не
rem засорять вывод.
where pip >nul 2>nul
if %ERRORLEVEL% equ 0 (
  echo Мы нашли pip. Устанавливаем все необходимое.
  call :pipInstallRequirements
) else (
  echo Ой. Мы не можем найти pip на вашем ПК.
  call conda install pip
  if %ERRORLEVEL% equ 0 (
    echo pip успешно установлен. Устанавливаем все необходимое.
    call :pipInstallRequirements
  ) else (
    echo Не удалось установить pip. Выходим...
    exit /b 1
  )
)

rem Если где-то выше произошла ошибка, выходим из скрипта.
if %ERRORLEVEL% neq 0 (
  exit /b 1
)

rem Запускаем скрипт main.py.
call python %~dp0src\main.py

goto :eof

rem Процедура устаноаки зависимостей из pip.
:pipInstallRequirements
echo Устанавливаем зависимости из pip.
pip install -r requirements.txt
if %ERRORLEVEL% neq 0 (
  echo Ой. Что-то пошло не так. Мы не можем установить зависимости из pip.
  echo Проверьте, установлен ли pip и настроен ли путь к нему.
  echo Выходим...
  exit /b 1
)
goto :eof

rem Процедура активации виртуального окружения.
:activateEnv
echo Окружение '%ENV_PREFIX%' найдено в Conda. Активируем его.
call conda activate %ENV_PREFIX%
if %ERRORLEVEL% equ 0 (
  echo Окружение '%ENV_PREFIX%' для Conda активировано.
) else (
  echo Не удалось активировать окружение '%ENV_PREFIX%' для Conda. Выходим...
  exit /b 1
)
goto :eof

rem Процедура запроса разрешения на создание нового виртуального окружения.
:promptToCreateNewEnv
echo Виртуальное окружение '%ENV_PREFIX%' не найдено в Conda.
echo Создать новое виртуальное окружение для Conda на основе Python 3.9?
echo Вы можете выбрать следующее, латинскими буквами:
echo ^ ^ y - создать новое виртуальное окружение
echo ^ ^ n - использовать текущее виртуальное окружение ^(%CONDA_DEFAULT_ENV%^)
echo ^ ^ a - отменить установку
set /p "NEW_ENV_RSP=Выберите значение [y/n/a]: "
rem Если пользователь хочет создать новое 'python39' окружение
if /i "!NEW_ENV_RSP!"=="y" (
  rem Создаем новое 'python39' окружение и активируем его
  call conda create --prefix %ENV_PREFIX% python=3.9
  call conda activate %ENV_PREFIX%
)
rem Если пользователь хочет использовать текущее виртуальное окружение
if /i "!NEW_ENV_RSP!"=="n" (
  rem Активируем текущее виртуальное окружение
  echo. >nul
)
rem Если пользователь хочет отменить установку
if /i "!NEW_ENV_RSP!"=="a" (
  echo Выход из скрипта...
  exit /b 1
)
goto :eof
