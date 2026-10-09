# Gemini Proxy Checker (VPS Edition)

Этот репозиторий содержит скрипты для автоматизированной проверки прокси-серверов на предмет их блокировки сервисом Google Gemini (как по API, так и через Web-интерфейс). Скрипты автоматически формируют конфигурацию для Shadowrocket (`shadowrocket.conf`) и отправляют уведомления в Telegram.

## Файлы в репозитории

* `checker.py` — основной скрипт-чекер. Запускает локальный xray, прогоняет через него все ноды из подписки и стучится к Gemini (API и Web). Удаляет нерабочие и те, на которые Google повесил флаг `locale=ru` (VPN-заглушка).
* `check_web_stub.py` — изолированный скрипт только для проверки Web-заглушек.
* `run.sh` — bash-скрипт оркестратор. Запускает синхронизацию подписок, затем чекер, и пушит обновлённый `shadowrocket.conf` обратно в этот репозиторий.
* `e0f_sub_server.py` — автономный сервер для управления подписками (в первую очередь для распределения Amnezia WG конфигов по отдельным профилям, управляемым через Telegram бота).
* `.env.example` — шаблон конфигурационного файла с ключами (переименуйте в `.env` на сервере).

## Как развернуть на своём сервере (VPS)

1. Клонируйте этот репозиторий:
```bash
git clone https://github.com/ВАШ_НИК/ВАШ_РЕПОЗИТОРИЙ.git /opt/gemini-proxy-checker
cd /opt/gemini-proxy-checker
```

2. Установите зависимости Python:
```bash
python3 -m venv venv
source venv/bin/activate
pip install requests pyyaml python-dotenv
```

3. Скачайте бинарник `xray` (Xray-core) и положите его в папку проекта. Убедитесь, что он исполняемый (`chmod +x xray`).

4. Создайте файл `.env`:
```bash
cp .env.example .env
nano .env
```

5. Настройте `cron` для регулярной проверки (например, каждые 30 минут):
```bash
crontab -e
# Добавьте строку:
*/30 * * * * cd /opt/gemini-proxy-checker && bash run.sh >> last_run.log 2>&1
```

## Как запустить Telegram-менеджер подписок (`e0f_sub_server.py`)

Если вам нужно управлять профилями подписок через Telegram, запустите сервер как systemd-службу:

1. Отредактируйте `.env` и добавьте `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` и `EOF_TOKEN`.
2. Запустите скрипт:
```bash
nohup /opt/gemini-proxy-checker/venv/bin/python3 /opt/gemini-proxy-checker/e0f_sub_server.py > /opt/gemini-proxy-checker/e0f_sub.log 2>&1 &
```
В Telegram боте используйте команды `/help`, `/newprofile`, `/profiles`, `/delprofile`.

## Требования

* Python 3.8+
* Xray-core
* Валидный ключ Google Gemini API (для проверки генерации контента)
* Токен Telegram бота (опционально, для отчётов)
