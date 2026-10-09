# 🚀 Gemini Proxy Checker & e0f Subscription Daemon (VPS Edition)

Комплексный автономный бэкенд для проверки прокси-узлов на доступность Google Gemini (Web + API), управления мультипрофильными подписками Shadowrocket (AmneziaWG, Hysteria2, VLESS, Mieru, TrustTunnel), веб-мониторинга и автоматической выгрузки музыки через Shazam Webhook в Telegram-канал.

---

## 🌟 Основные возможности

### 1. 🤖 Умный чекер Google Gemini (Web & API)
* **Мультипротокольное тестирование:** Ephemeral-инстансы **Xray-core** (VLESS, Trojan, Shadowsocks) и **sing-box** (Hysteria 2).
* **Dual-Verification:**
  * **Gemini Web:** Проверка на `gemini.google.com` с инспекцией WIZ-токенов гео-блокировки (`RU`, `BY`, заглушка недоступности сервиса в регионе).
  * **Gemini API:** Реальный запрос `generateContent` к модели Gemini API с проверкой генерации текста.
* **Автоматическая сборка `shadowrocket.conf`:**
  * Группа `GEMINI2` — узлы, открывающие веб-интерфейс без заглушек.
  * Группа `GEMINI` — узлы с рабочим доступом к Gemini API.
* **Smart Quick-Check:** Легковесный скрипт `quick_check.sh` проверяет только ранее работавшие ноды каждые 10 минут, экономя ресурсы и квоты API. При падении хотя бы одного сервера автоматически запускается полный цикл.
* **История состояния:** Сохранение истории последних 48 проверок в `checker_state.json`.

### 2. 📦 Демон подписок e0f.cx & AmneziaWG
* **Мультипрофильность:** Создание независимых изолированных профилей (например, `Xan`, `iya`) через Telegram-бота.
* **AmneziaWG (AWG 2.0 & 3.1):** Автоматическая генерация и ротация пиров в API e0f, распределение конфигов без превышения лимита слотов.
* **Дополнительные протоколы:** Включение общих узлов TrustTunnel, Mieru и Hysteria2 в единую подписку.
* **Автономный дисковый кэш:** При любых сбоях API e0f или истечении токена сервис мгновенно загружает локальный кэш с диска — подписки клиентов никогда не сбрасываются в ноль.

### 3. 🎵 Shazam & Music Pipeline (Автоматизация выгрузки в канал)
* **Apple Shortcuts Webhook (`/shazam`, `/music`):** При распознавании трека на iPhone шорткат делает мгновенный запрос на сервер и сразу завершает работу, не зависая в ожидании.
* **Поддержка GET и POST:** Приём параметров через строку URL (`?token=...&q=...` или `&artist=...&title=...`), JSON-тело или заголовки.
* **Защита токеном:** Доступ к вебхуку закрыт секретным токеном `SHAZAM_SECRET_TOKEN`.
* **Умный поиск и авто-дедупликация:**
  * Поиск лучшей аудиодорожки через `yt-dlp` и конвертация в 320 kbps MP3 со встраиванием обложки.
  * Автоматическое удаление дублирования исполнителя в названии (`Moby — Moby - Natural Blues` ➔ `Moby — Natural Blues`) и очистка названий от мусора клипов (`Official Video`, `Lyric Video` и т.д.).
* **Интерактивное подтверждение в Telegram:**
  * Скачанный трек с плеером отправляется в личные сообщения владельцу с кнопками `[✅ Закинуть в канал]` и `[❌ Отмена]`.
  * При подтверждении аудиофайл с чистыми тегами публикуется в целевой Telegram-канал («Свалка треков»).
  * При отмене или публикации временный MP3 удаляется с сервера, а аудиосообщение аккуратно удаляется из лички, не засоряя чат.
* **Прямой поиск в боте:** Отправка названия трека текстом в диалог с ботом или команда `/music <название>`.

### 4. 🌐 Nginx Reverse Proxy & Веб-страница статуса
* Публичный веб-мониторинг на `/status` (темная минималистичная тема, отображение зеленых/красных индикаторов Gemini-узлов, счетчики подписок, история проверок, мета-автообновление каждые 60 секунд).
* Защита эндпоинтов подписок `/sub` и `/awg` через Nginx rate-limiting (`limit_req`).
* Эндпоинт проверки здоровья `/health`.

---

## 📁 Структура проекта

```text
/opt/gemini-proxy-checker/
├── checker.py             # Основной чекер узлов (Xray + sing-box) для Gemini Web и API
├── check_web_stub.py      # Изолированный скрипт детекции региональных заглушек Google
├── e0f_sub_server.py      # Автономный сервер подписок, Telegram-бот и Shazam-вебхук
├── quick_check.sh         # Быстрая проверка активных узлов (Smart Cron)
├── run.sh                 # Оркестратор полного цикла проверки и Git-синхронизации
├── shadowrocket.conf      # Сгенерированный актуальный конфиг для Shadowrocket
├── .env.example           # Пример конфигурационного файла с переменными окружения
├── .gitignore             # Исключение секретов, локальных кэшей и временных файлов
└── README.md              # Документация проекта
```

---

## ⚙️ Установка и развёртывание на VPS

### 1. Системные зависимости
```bash
apt-get update && apt-get install -y nginx ffmpeg python3 python3-venv git curl
```

### 2. Установка Xray-core и sing-box
```bash
# Xray-core
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)"

# sing-box (для Hysteria 2)
bash -c "$(curl -fsSL https://sing-box.app/deb-install.sh)"
```

### 3. Клонирование репозитория и установка Python-окружения
```bash
git clone git@github.com:teddyxanya/Gemini-Proxy-Checker.git /opt/gemini-proxy-checker
cd /opt/gemini-proxy-checker

python3 -m venv venv
source venv/bin/activate
pip install requests pyyaml python-dotenv yt-dlp
```

### 4. Настройка окружения (`.env`)
Скопируйте пример конфига и заполните свои значения:
```bash
cp .env.example .env
nano .env
```

Пример `.env`:
```ini
# Ссылка на базовую подписку прокси (VLESS, Trojan, SS)
SUB_URL="https://your-provider.com/sub/YOUR_KEY"

# Ключ Google Gemini API
GEMINI_API_KEY="AIzaSy..."

# Telegram бот
TELEGRAM_BOT_TOKEN="1234567890:ABCdef..."
TELEGRAM_CHAT_ID="12345678"
TELEGRAM_OWNER_ID="12345678"

# Музыкальный канал для публикаций
MUSIC_CHANNEL_ID="-1001234567890"

# Токен для интеграции Shazam / Apple Shortcuts
SHAZAM_SECRET_TOKEN="your_random_secret_token"

# Токен провайдера e0f.cx
EOF_TOKEN="eyJhbGciOi..."
SECRET_TOKEN="your_default_secret_sub_token"
VPS_IP="127.0.0.1"
PORT=8088

# Git авто-пуш
GIT_REPO_URL="git@github.com:teddyxanya/Gemini-Proxy-Checker.git"
GIT_BRANCH="main"
CONF_PATH="/opt/gemini-proxy-checker/shadowrocket.conf"
```

---

## 🛠 Настройка Nginx и Systemd

### 1. Nginx конфиг (`/etc/nginx/sites-available/gemini-checker`)
```nginx
limit_req_zone $binary_remote_addr zone=sub:10m rate=10r/m;

server {
    listen 8081;
    server_name _;

    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;

    location = /status {
        proxy_pass http://127.0.0.1:8088/status;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location = /health {
        proxy_pass http://127.0.0.1:8088/health;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location ~ ^/(sub|awg)$ {
        limit_req zone=sub burst=5 nodelay;
        proxy_pass http://127.0.0.1:8088;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 30s;
    }

    location / {
        proxy_pass http://127.0.0.1:8088;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 30s;
    }
}
```
Активируйте сайт и перезапустите Nginx:
```bash
ln -s /etc/nginx/sites-available/gemini-checker /etc/nginx/sites-enabled/
nginx -t && systemctl restart nginx
```

### 2. Systemd служба (`/etc/systemd/system/e0f-sub.service`)
```ini
[Unit]
Description=e0f.cx Private AWG Subscription & Music Daemon
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/gemini-proxy-checker
ExecStart=/opt/gemini-proxy-checker/venv/bin/python3 /opt/gemini-proxy-checker/e0f_sub_server.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Запуск службы:
```bash
systemctl daemon-reload
systemctl enable --now e0f-sub
```

### 3. Расписание Cron (`crontab -e`)
```cron
# Полный прогон чекера каждые 3 часа
0 */3 * * * /opt/gemini-proxy-checker/run.sh >> /var/log/gemini-proxy-checker.log 2>&1

# Быстрая проверка только рабочих Gemini узлов каждые 10 минут
*/10 * * * * /opt/gemini-proxy-checker/quick_check.sh >> /var/log/gemini-quick-check.log 2>&1
```

---

## 📱 Настройка Apple Shortcuts (Шорткат на iPhone)

Сборка шортката в приложении **«Команды»** на iOS:

1. **Действие 1:** `Распознать музыку с помощью Shazam`.
2. **Действие 2:** `Текст`:
   ```text
   http://YOUR_VPS_IP:8081/shazam?token=YOUR_SHAZAM_SECRET_TOKEN&artist=[Исполнитель]&title=[Название]
   ```
   *(Вставляя синюю плашку `Медиафайлы Shazam`, нажмите на неё пальцем и выберите для первой переменной «Исполнитель», а для второй — «Название»).*
3. **Действие 3:** `Получить содержимое URL` (передать блок `Текст`, метод по умолчанию: `GET`).
4. **Действие 4:** `Показать уведомление`: `Трек отправлен в бота! 🎧`.

---

## 🤖 Команды Telegram-бота

| Команда | Описание |
| :--- | :--- |
| `/status` | Статус рабочих серверов Gemini, время следующей проверки и профили подписок |
| `/profiles` | Список профилей и персональные ссылки для добавления в Shadowrocket |
| `/newprofile <имя>` | Создать новый изолированный профиль с AmneziaWG пирами |
| `/delprofile <имя>` | Удалить профиль и освободить слоты на e0f |
| `/check` | Принудительный запуск полной проверки серверов (только для владельца) |
| `/sync` | Принудительная синхронизация подписок и пиров с e0f API |
| `/music <название>` | Поиск и скачивание трека с предпросмотром и кнопками подтверждения |

---

## 🔒 Безопасность
* Все приватные токены, ключи и Telegram ID хранятся исключительно в нетрекаемом файле `.env`.
* История Git очищена от чувствительных данных.
* Shazam-вебхук защищён проверкой секретного токена.
* Публикация музыки в канал защищена двухэтапным подтверждением владельцем.
* Эндпоинты подписок защищены ограничением частоты запросов (rate limiting).
