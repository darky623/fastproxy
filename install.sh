#!/bin/bash
set -e

# FastProxy Installer for Ubuntu 24.04
# Панель управления HAProxy на базе FastAPI

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

INSTALL_DIR="/opt/fastproxy"
HAPROXY_CFG="/etc/haproxy/haproxy.cfg"
HAPROXY_MAPS_DIR="/etc/haproxy/maps"
HAPROXY_CERTS_DIR="/etc/haproxy/certs"

# URL репозитория для скачивания файлов
REPO_RAW_URL="https://raw.githubusercontent.com/darky623/fastproxy/main"

echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║       FastProxy Installer v1.0             ║${NC}"
echo -e "${GREEN}║   HAProxy Management Panel for Ubuntu      ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"
echo ""

# Проверка root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Ошибка: Этот скрипт должен быть запущен от root${NC}"
   exit 1
fi

# Проверка Ubuntu
if ! grep -q "Ubuntu" /etc/os-release 2>/dev/null; then
    echo -e "${YELLOW}Предупреждение: Этот скрипт оптимизирован для Ubuntu 24.04${NC}"
fi

echo -e "${YELLOW}[1/9] Обновление системы и установка зависимостей...${NC}"
apt-get update -qq
apt-get install -y -qq haproxy certbot python3 python3-pip python3-venv openssl curl > /dev/null

echo -e "${YELLOW}[2/9] Создание директорий...${NC}"
mkdir -p "$INSTALL_DIR"
mkdir -p "$HAPROXY_MAPS_DIR"
mkdir -p "$HAPROXY_CERTS_DIR"
mkdir -p "$INSTALL_DIR/templates"

# Генерация пароля администратора
echo -e "${YELLOW}[3/9] Генерация учетных данных администратора...${NC}"
if [ ! -f "$INSTALL_DIR/.admin_password" ]; then
    ADMIN_PASSWORD=$(openssl rand -base64 16 | tr -d '=/+' | head -c 16)
    echo "$ADMIN_PASSWORD" > "$INSTALL_DIR/.admin_password"
    chmod 600 "$INSTALL_DIR/.admin_password"
    NEW_INSTALL=true
else
    ADMIN_PASSWORD=$(cat "$INSTALL_DIR/.admin_password")
    NEW_INSTALL=false
fi

# Генерация секретного ключа для JWT
if [ ! -f "$INSTALL_DIR/.jwt_secret" ]; then
    JWT_SECRET=$(openssl rand -hex 32)
    echo "$JWT_SECRET" > "$INSTALL_DIR/.jwt_secret"
    chmod 600 "$INSTALL_DIR/.jwt_secret"
fi

echo -e "${YELLOW}[4/9] Скачивание файлов приложения...${NC}"

# Функция для скачивания файла
download_file() {
    local url="$1"
    local dest="$2"
    echo "  Скачивание: $(basename "$dest")"
    if ! curl -fsSL "$url" -o "$dest"; then
        echo -e "${RED}Ошибка скачивания: $url${NC}"
        exit 1
    fi
}

# Проверяем, запущен ли скрипт локально (файлы рядом) или через curl
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" 2>/dev/null)" 2>/dev/null && pwd)" || SCRIPT_DIR=""

if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/main.py" ] && [ -f "$SCRIPT_DIR/requirements.txt" ]; then
    echo "  Используются локальные файлы из: $SCRIPT_DIR"
    cp "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/main.py" "$INSTALL_DIR/"
    [ -f "$SCRIPT_DIR/templates/index.html" ] && cp "$SCRIPT_DIR/templates/index.html" "$INSTALL_DIR/templates/"
else
    echo "  Скачивание из репозитория: $REPO_RAW_URL"
    download_file "$REPO_RAW_URL/requirements.txt" "$INSTALL_DIR/requirements.txt"
    download_file "$REPO_RAW_URL/main.py" "$INSTALL_DIR/main.py"
    download_file "$REPO_RAW_URL/templates/index.html" "$INSTALL_DIR/templates/index.html"
fi

echo -e "${YELLOW}[5/9] Настройка Python окружения...${NC}"
python3 -m venv "$INSTALL_DIR/venv"
source "$INSTALL_DIR/venv/bin/activate"

echo -e "${YELLOW}[6/9] Установка Python зависимостей...${NC}"
pip install --quiet --upgrade pip
pip install --quiet -r "$INSTALL_DIR/requirements.txt"

echo -e "${YELLOW}[7/9] Настройка HAProxy...${NC}"
# Создание пустого map-файла
touch "$HAPROXY_MAPS_DIR/domain_backend.map"

# Создание placeholder сертификата для HAProxy (чтобы он мог запуститься)
if [ ! -f "$HAPROXY_CERTS_DIR/placeholder.pem" ]; then
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$HAPROXY_CERTS_DIR/placeholder.key" \
        -out "$HAPROXY_CERTS_DIR/placeholder.crt" \
        -subj "/CN=localhost" 2>/dev/null
    cat "$HAPROXY_CERTS_DIR/placeholder.crt" "$HAPROXY_CERTS_DIR/placeholder.key" > "$HAPROXY_CERTS_DIR/placeholder.pem"
    rm "$HAPROXY_CERTS_DIR/placeholder.key" "$HAPROXY_CERTS_DIR/placeholder.crt"
fi

# Бэкап оригинального конфига
if [ -f "$HAPROXY_CFG" ] && [ ! -f "$HAPROXY_CFG.original" ]; then
    cp "$HAPROXY_CFG" "$HAPROXY_CFG.original"
fi

# Создание базового конфига HAProxy
cat > "$HAPROXY_CFG" << 'HAPROXY_CONFIG'
global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

    # SSL настройки
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

defaults
    log     global
    mode    http
    option  httplog
    option  dontlognull
    option  forwardfor
    timeout connect 5000
    timeout client  50000
    timeout server  50000
    errorfile 400 /etc/haproxy/errors/400.http
    errorfile 403 /etc/haproxy/errors/403.http
    errorfile 408 /etc/haproxy/errors/408.http
    errorfile 500 /etc/haproxy/errors/500.http
    errorfile 502 /etc/haproxy/errors/502.http
    errorfile 503 /etc/haproxy/errors/503.http
    errorfile 504 /etc/haproxy/errors/504.http

frontend http_front
    bind *:80
    http-request redirect scheme https unless { ssl_fc }
    default_backend no_backend

frontend https_front
    bind *:443 ssl crt /etc/haproxy/certs/ alpn h2,http/1.1
    http-request set-header X-Forwarded-Proto https
    http-request set-header X-Real-IP %[src]
    use_backend %[req.hdr(host),lower,map(/etc/haproxy/maps/domain_backend.map)] if { req.hdr(host),lower,map(/etc/haproxy/maps/domain_backend.map) -m found }
    default_backend no_backend

backend no_backend
    http-request deny deny_status 503

# Динамические backend-секции добавляются ниже панелью управления
HAPROXY_CONFIG

# Проверка конфигурации HAProxy
if haproxy -c -f "$HAPROXY_CFG" > /dev/null 2>&1; then
    systemctl restart haproxy
    systemctl enable haproxy
else
    echo -e "${RED}Ошибка в конфигурации HAProxy!${NC}"
fi

echo -e "${YELLOW}[8/9] Настройка systemd сервиса...${NC}"
cat > /etc/systemd/system/fastproxy.service << SYSTEMD_SERVICE
[Unit]
Description=FastProxy HAProxy Management Panel
After=network.target haproxy.service
Wants=haproxy.service

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
ExecStart=$INSTALL_DIR/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8080
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SYSTEMD_SERVICE

systemctl daemon-reload
systemctl enable fastproxy
systemctl restart fastproxy

echo -e "${YELLOW}[9/9] Настройка автообновления сертификатов...${NC}"
# Создание директории для хуков certbot (если certbot ещё не запускался)
mkdir -p /etc/letsencrypt/renewal-hooks/deploy

# Создание хука для certbot
cat > /etc/letsencrypt/renewal-hooks/deploy/haproxy-reload.sh << 'CERTBOT_HOOK'
#!/bin/bash
# Хук для автоматической склейки сертификатов после обновления

for domain in $RENEWED_DOMAINS; do
    LIVE_DIR="/etc/letsencrypt/live/$domain"
    HAPROXY_CERT="/etc/haproxy/certs/${domain}.pem"
    
    if [ -f "$LIVE_DIR/fullchain.pem" ] && [ -f "$LIVE_DIR/privkey.pem" ]; then
        cat "$LIVE_DIR/fullchain.pem" "$LIVE_DIR/privkey.pem" > "$HAPROXY_CERT"
        chmod 600 "$HAPROXY_CERT"
    fi
done

# Проверка и перезагрузка HAProxy
if haproxy -c -f /etc/haproxy/haproxy.cfg > /dev/null 2>&1; then
    systemctl reload haproxy
fi
CERTBOT_HOOK

chmod +x /etc/letsencrypt/renewal-hooks/deploy/haproxy-reload.sh

# Настройка cron для автообновления (certbot обычно уже настраивает это)
if ! crontab -l 2>/dev/null | grep -q "certbot renew"; then
    (crontab -l 2>/dev/null; echo "0 3 * * * /usr/bin/certbot renew --quiet") | crontab -
fi

# Получение IP адреса сервера
SERVER_IP=$(hostname -I | awk '{print $1}')

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║            Установка завершена успешно!                    ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}Панель управления:${NC} http://${SERVER_IP}:8080"
echo ""
echo -e "${GREEN}Учетные данные:${NC}"
echo -e "  Логин:   ${YELLOW}admin${NC}"
echo -e "  Пароль:  ${YELLOW}${ADMIN_PASSWORD}${NC}"
echo ""
if [ "$NEW_INSTALL" = true ]; then
    echo -e "${RED}ВАЖНО: Сохраните пароль! Он больше не будет показан.${NC}"
fi
echo ""
echo -e "${GREEN}Управление сервисом:${NC}"
echo "  systemctl status fastproxy   - статус"
echo "  systemctl restart fastproxy  - перезапуск"
echo "  journalctl -u fastproxy -f   - логи"
echo ""
