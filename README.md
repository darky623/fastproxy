# FastProxy - HAProxy Management Panel

Панель управления прокси-сервером на базе HAProxy с веб-интерфейсом на FastAPI.

## Возможности

- Веб-интерфейс для управления доменами и прокси
- Автоматический выпуск SSL-сертификатов через Let's Encrypt (Certbot)
- Два режима SSL: Termination и Re-encrypt
- Автоматическое обновление сертификатов
- Хранение настроек в SQLite
- Проверка конфигурации HAProxy перед применением

## Требования

- Ubuntu 24.04 (или совместимый дистрибутив)
- Root доступ
- Открытые порты: 80, 443, 8080

## Установка

### Быстрая установка (одной командой)

Скрипт автоматически скачает все необходимые файлы из GitHub:

```bash
curl -sSL https://raw.githubusercontent.com/darky623/fastproxy/main/install.sh | sudo bash
```

### Локальная установка

Если файлы уже скачаны локально, скрипт использует их вместо скачивания:

```bash
git clone https://github.com/darky623/fastproxy.git
cd fastproxy
chmod +x install.sh
sudo ./install.sh
```

### Как это работает

Скрипт `install.sh` автоматически определяет способ запуска:
- **Локально** (файлы рядом): копирует `main.py`, `requirements.txt`, `templates/index.html`
- **Через curl**: скачивает файлы из GitHub репозитория

После установки скрипт выведет:
- URL панели управления (http://IP:8080)
- Логин: `admin`
- Пароль: (сгенерированный случайно)

**Сохраните пароль!** Он больше не будет показан.

## Использование

### Добавление домена

1. Откройте панель управления в браузере
2. Нажмите "Add Domain"
3. Введите:
   - **Domain**: ваш домен (например, `example.com`)
   - **Backend IP**: IP-адрес бэкенд-сервера
   - **Port**: порт бэкенд-сервера
   - **SSL Mode**:
     - **SSL Termination**: HAProxy терминирует SSL, подключается к бэкенду по HTTP
     - **SSL Re-encrypt**: HAProxy терминирует SSL и переподключается к бэкенду по HTTPS

4. После добавления домена нажмите на иконку щита для выпуска SSL-сертификата

### Управление сертификатами

- Сертификаты выпускаются через Certbot (Let's Encrypt)
- Автоматическое обновление настроено через cron
- Статусы сертификатов:
  - **Valid** - действителен
  - **Warning** - истекает менее чем через 30 дней
  - **Expiring soon** - истекает менее чем через 7 дней
  - **Expired** - просрочен
  - **Not issued** - не выпущен

## Управление сервисом

```bash
# Статус
sudo systemctl status fastproxy

# Перезапуск
sudo systemctl restart fastproxy

# Логи
sudo journalctl -u fastproxy -f

# Статус HAProxy
sudo systemctl status haproxy
```

## Структура файлов

```
/opt/fastproxy/
├── main.py              # FastAPI приложение
├── requirements.txt     # Python зависимости
├── templates/
│   └── index.html       # Веб-интерфейс
├── fastproxy.db         # SQLite база данных
├── .admin_password      # Пароль администратора
└── .jwt_secret          # Секретный ключ JWT

/etc/haproxy/
├── haproxy.cfg          # Конфигурация HAProxy
├── maps/
│   └── domain_backend.map  # Маппинг доменов на бэкенды
└── certs/
    └── *.pem            # SSL сертификаты
```

## API Endpoints

| Метод | Путь | Описание |
|-------|------|----------|
| POST | `/api/login` | Авторизация |
| GET | `/api/domains` | Список доменов |
| POST | `/api/domains` | Добавление домена |
| DELETE | `/api/domains/{id}` | Удаление домена |
| POST | `/api/domains/{id}/cert` | Выпуск сертификата |
| GET | `/api/health` | Статус сервиса |

## Безопасность

- JWT-токены для авторизации (срок действия 24 часа)
- Пароль хранится в bcrypt-хеше
- Проверка конфигурации HAProxy перед применением
- Рекомендуется: настроить firewall и использовать VPN для доступа к порту 8080

## Troubleshooting

### HAProxy не запускается

```bash
# Проверка конфигурации
sudo haproxy -c -f /etc/haproxy/haproxy.cfg

# Просмотр ошибок
sudo journalctl -u haproxy -n 50
```

### Сертификат не выпускается

1. Убедитесь, что домен указывает на IP сервера
2. Проверьте, что порт 80 доступен извне
3. Посмотрите логи: `sudo journalctl -u fastproxy -n 50`

### Сброс пароля

```bash
# Сгенерировать новый пароль
NEW_PASS=$(openssl rand -base64 16 | tr -d '=/+' | head -c 16)
echo "$NEW_PASS" | sudo tee /opt/fastproxy/.admin_password
sudo rm /opt/fastproxy/fastproxy.db  # Удалить БД для сброса хеша
sudo systemctl restart fastproxy
echo "Новый пароль: $NEW_PASS"
```

## Лицензия

MIT
