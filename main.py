"""
FastProxy - HAProxy Management Panel
Панель управления прокси-сервером на базе HAProxy
"""

import os
import re
import subprocess
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, field_validator
from sqlalchemy import create_engine, Column, Integer, String, DateTime, event
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from jose import JWTError, jwt

# ============================================================================
# Конфигурация
# ============================================================================

INSTALL_DIR = Path("/opt/fastproxy")
DB_PATH = INSTALL_DIR / "fastproxy.db"
PASSWORD_FILE = INSTALL_DIR / ".admin_password"
JWT_SECRET_FILE = INSTALL_DIR / ".jwt_secret"
HAPROXY_CFG = Path("/etc/haproxy/haproxy.cfg")
HAPROXY_MAP = Path("/etc/haproxy/maps/domain_backend.map")
HAPROXY_CERTS_DIR = Path("/etc/haproxy/certs")
LETSENCRYPT_LIVE = Path("/etc/letsencrypt/live")

# Для разработки: если файлы не существуют, используем локальные пути
if not INSTALL_DIR.exists():
    INSTALL_DIR = Path(".")
    DB_PATH = INSTALL_DIR / "fastproxy.db"
    PASSWORD_FILE = INSTALL_DIR / ".admin_password"
    JWT_SECRET_FILE = INSTALL_DIR / ".jwt_secret"

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24

# ============================================================================
# База данных
# ============================================================================

DATABASE_URL = f"sqlite:///{DB_PATH}"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Domain(Base):
    """Модель домена в базе данных"""
    __tablename__ = "domains"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, unique=True, index=True, nullable=False)
    backend_ip = Column(String, nullable=False)
    backend_port = Column(Integer, nullable=False)
    ssl_mode = Column(String, default="termination")  # termination | reencrypt
    cert_expiry = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class Settings(Base):
    """Модель настроек"""
    __tablename__ = "settings"

    id = Column(Integer, primary_key=True)
    key = Column(String, unique=True, nullable=False)
    value = Column(String, nullable=False)


# Создание таблиц
Base.metadata.create_all(bind=engine)

# ============================================================================
# Хелперы
# ============================================================================

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()


def get_db():
    """Получение сессии БД"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_jwt_secret() -> str:
    """Получение секретного ключа JWT"""
    if JWT_SECRET_FILE.exists():
        return JWT_SECRET_FILE.read_text().strip()
    # Fallback для разработки
    return "dev-secret-key-change-in-production"


def get_admin_password() -> str:
    """Получение пароля администратора"""
    if PASSWORD_FILE.exists():
        return PASSWORD_FILE.read_text().strip()
    return "admin"  # Fallback для разработки


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Проверка пароля"""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Хеширование пароля"""
    return pwd_context.hash(password)


def create_access_token(data: dict) -> str:
    """Создание JWT токена"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, get_jwt_secret(), algorithm=ALGORITHM)


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """Верификация JWT токена"""
    try:
        payload = jwt.decode(credentials.credentials, get_jwt_secret(), algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def init_admin_password(db: Session):
    """Инициализация пароля администратора в БД"""
    setting = db.query(Settings).filter(Settings.key == "admin_password_hash").first()
    if not setting:
        plain_password = get_admin_password()
        hashed = get_password_hash(plain_password)
        setting = Settings(key="admin_password_hash", value=hashed)
        db.add(setting)
        db.commit()


# ============================================================================
# HAProxy функции
# ============================================================================

def sanitize_backend_name(domain: str) -> str:
    """Преобразование домена в валидное имя backend"""
    return re.sub(r'[^a-zA-Z0-9]', '_', domain)


def generate_haproxy_config(domains: list[Domain]) -> str:
    """Генерация конфигурации HAProxy"""
    config = '''global
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

'''
    
    # Генерация backend секций для каждого домена
    for domain in domains:
        backend_name = sanitize_backend_name(domain.domain)
        ssl_options = ""
        
        if domain.ssl_mode == "reencrypt":
            ssl_options = " ssl verify none"
        
        config += f'''backend {backend_name}
    server srv1 {domain.backend_ip}:{domain.backend_port}{ssl_options} check

'''
    
    return config


def generate_domain_map(domains: list[Domain]) -> str:
    """Генерация map-файла для HAProxy"""
    lines = []
    for domain in domains:
        backend_name = sanitize_backend_name(domain.domain)
        lines.append(f"{domain.domain} {backend_name}")
    return "\n".join(lines) + "\n" if lines else ""


def validate_haproxy_config() -> tuple[bool, str]:
    """Проверка конфигурации HAProxy"""
    try:
        result = subprocess.run(
            ["haproxy", "-c", "-f", str(HAPROXY_CFG)],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            return True, "Configuration valid"
        return False, result.stderr
    except subprocess.TimeoutExpired:
        return False, "Validation timeout"
    except FileNotFoundError:
        return False, "HAProxy not found"
    except Exception as e:
        return False, str(e)


def apply_haproxy_config(domains: list[Domain]) -> tuple[bool, str]:
    """Применение новой конфигурации HAProxy"""
    # Генерация конфигов
    config = generate_haproxy_config(domains)
    domain_map = generate_domain_map(domains)
    
    # Бэкап текущих файлов
    backup_cfg = HAPROXY_CFG.with_suffix('.cfg.bak')
    backup_map = HAPROXY_MAP.with_suffix('.map.bak')
    
    try:
        if HAPROXY_CFG.exists():
            shutil.copy(HAPROXY_CFG, backup_cfg)
        if HAPROXY_MAP.exists():
            shutil.copy(HAPROXY_MAP, backup_map)
        
        # Запись новых файлов
        HAPROXY_CFG.write_text(config)
        HAPROXY_MAP.parent.mkdir(parents=True, exist_ok=True)
        HAPROXY_MAP.write_text(domain_map)
        
        # Проверка конфигурации
        valid, message = validate_haproxy_config()
        if not valid:
            # Откат при ошибке
            if backup_cfg.exists():
                shutil.copy(backup_cfg, HAPROXY_CFG)
            if backup_map.exists():
                shutil.copy(backup_map, HAPROXY_MAP)
            return False, f"Configuration validation failed: {message}"
        
        # Перезагрузка HAProxy
        result = subprocess.run(
            ["systemctl", "reload", "haproxy"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode != 0:
            return False, f"Failed to reload HAProxy: {result.stderr}"
        
        return True, "Configuration applied successfully"
        
    except Exception as e:
        # Откат при ошибке
        if backup_cfg.exists():
            shutil.copy(backup_cfg, HAPROXY_CFG)
        if backup_map.exists():
            shutil.copy(backup_map, HAPROXY_MAP)
        return False, str(e)


# ============================================================================
# Certbot функции
# ============================================================================

def issue_certificate(domain: str) -> tuple[bool, str]:
    """Выпуск SSL сертификата через Certbot"""
    try:
        # Остановка HAProxy для освобождения порта 80
        subprocess.run(["systemctl", "stop", "haproxy"], timeout=10)
        
        result = subprocess.run(
            [
                "certbot", "certonly",
                "--standalone",
                "--non-interactive",
                "--agree-tos",
                "--register-unsafely-without-email",
                "-d", domain
            ],
            capture_output=True,
            text=True,
            timeout=120
        )
        
        # Запуск HAProxy обратно
        subprocess.run(["systemctl", "start", "haproxy"], timeout=10)
        
        if result.returncode != 0:
            return False, result.stderr
        
        # Склейка сертификатов для HAProxy
        success, message = merge_certificate(domain)
        if not success:
            return False, message
        
        return True, "Certificate issued successfully"
        
    except subprocess.TimeoutExpired:
        subprocess.run(["systemctl", "start", "haproxy"], timeout=10)
        return False, "Certificate issuance timeout"
    except Exception as e:
        subprocess.run(["systemctl", "start", "haproxy"], timeout=10)
        return False, str(e)


def merge_certificate(domain: str) -> tuple[bool, str]:
    """Склейка сертификатов для HAProxy"""
    try:
        live_dir = LETSENCRYPT_LIVE / domain
        fullchain = live_dir / "fullchain.pem"
        privkey = live_dir / "privkey.pem"
        
        if not fullchain.exists() or not privkey.exists():
            return False, f"Certificate files not found for {domain}"
        
        HAPROXY_CERTS_DIR.mkdir(parents=True, exist_ok=True)
        output_pem = HAPROXY_CERTS_DIR / f"{domain}.pem"
        
        with open(output_pem, 'w') as out:
            out.write(fullchain.read_text())
            out.write(privkey.read_text())
        
        os.chmod(output_pem, 0o600)
        
        return True, "Certificate merged successfully"
        
    except Exception as e:
        return False, str(e)


def get_certificate_expiry(domain: str) -> Optional[datetime]:
    """Получение даты истечения сертификата"""
    try:
        cert_path = HAPROXY_CERTS_DIR / f"{domain}.pem"
        if not cert_path.exists():
            return None
        
        result = subprocess.run(
            ["openssl", "x509", "-enddate", "-noout", "-in", str(cert_path)],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            # Парсинг даты: notAfter=Mar 15 12:00:00 2024 GMT
            match = re.search(r'notAfter=(.+)', result.stdout)
            if match:
                date_str = match.group(1).strip()
                return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
        
        return None
    except Exception:
        return None


def delete_certificate(domain: str) -> tuple[bool, str]:
    """Удаление сертификата"""
    try:
        # Удаление из HAProxy
        cert_path = HAPROXY_CERTS_DIR / f"{domain}.pem"
        if cert_path.exists():
            cert_path.unlink()
        
        # Удаление из Let's Encrypt (опционально)
        subprocess.run(
            ["certbot", "delete", "--cert-name", domain, "--non-interactive"],
            capture_output=True,
            timeout=30
        )
        
        return True, "Certificate deleted"
    except Exception as e:
        return False, str(e)


# ============================================================================
# FastAPI приложение
# ============================================================================

app = FastAPI(title="FastProxy", description="HAProxy Management Panel")

# Подключение шаблонов
templates_dir = Path(__file__).parent / "templates"
if templates_dir.exists():
    templates = Jinja2Templates(directory=str(templates_dir))
else:
    templates = None


# ============================================================================
# Pydantic модели
# ============================================================================

class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class DomainCreate(BaseModel):
    domain: str
    backend_ip: str
    backend_port: int
    ssl_mode: str = "termination"
    
    @field_validator('domain')
    @classmethod
    def validate_domain(cls, v):
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', v):
            raise ValueError('Invalid domain format')
        return v.lower()
    
    @field_validator('backend_ip')
    @classmethod
    def validate_ip(cls, v):
        # Простая валидация IP
        parts = v.split('.')
        if len(parts) != 4:
            raise ValueError('Invalid IP format')
        for part in parts:
            if not part.isdigit() or not 0 <= int(part) <= 255:
                raise ValueError('Invalid IP format')
        return v
    
    @field_validator('backend_port')
    @classmethod
    def validate_port(cls, v):
        if not 1 <= v <= 65535:
            raise ValueError('Port must be between 1 and 65535')
        return v
    
    @field_validator('ssl_mode')
    @classmethod
    def validate_ssl_mode(cls, v):
        if v not in ('termination', 'reencrypt'):
            raise ValueError('ssl_mode must be "termination" or "reencrypt"')
        return v


class DomainResponse(BaseModel):
    id: int
    domain: str
    backend_ip: str
    backend_port: int
    ssl_mode: str
    cert_expiry: Optional[datetime]
    cert_status: str
    created_at: datetime

    class Config:
        from_attributes = True


# ============================================================================
# Роуты
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Инициализация при запуске"""
    db = SessionLocal()
    try:
        init_admin_password(db)
    finally:
        db.close()


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Главная страница"""
    if templates:
        return templates.TemplateResponse("index.html", {"request": request})
    return HTMLResponse("<h1>FastProxy</h1><p>Templates not found</p>")


@app.post("/api/login", response_model=LoginResponse)
async def login(data: LoginRequest, db: Session = Depends(get_db)):
    """Авторизация"""
    if data.username != "admin":
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    setting = db.query(Settings).filter(Settings.key == "admin_password_hash").first()
    if not setting:
        raise HTTPException(status_code=500, detail="Admin password not configured")
    
    if not verify_password(data.password, setting.value):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_access_token({"sub": data.username})
    return LoginResponse(access_token=token)


@app.get("/api/domains", response_model=list[DomainResponse])
async def list_domains(
    db: Session = Depends(get_db),
    _: str = Depends(verify_token)
):
    """Список всех доменов"""
    domains = db.query(Domain).all()
    result = []
    
    for domain in domains:
        # Определение статуса сертификата
        cert_expiry = get_certificate_expiry(domain.domain)
        if cert_expiry:
            domain.cert_expiry = cert_expiry
            db.commit()
            
            days_left = (cert_expiry - datetime.utcnow()).days
            if days_left < 0:
                cert_status = "expired"
            elif days_left < 7:
                cert_status = "expiring_soon"
            elif days_left < 30:
                cert_status = "warning"
            else:
                cert_status = "valid"
        else:
            cert_status = "missing"
        
        result.append(DomainResponse(
            id=domain.id,
            domain=domain.domain,
            backend_ip=domain.backend_ip,
            backend_port=domain.backend_port,
            ssl_mode=domain.ssl_mode,
            cert_expiry=domain.cert_expiry,
            cert_status=cert_status,
            created_at=domain.created_at
        ))
    
    return result


@app.post("/api/domains", response_model=DomainResponse)
async def create_domain(
    data: DomainCreate,
    db: Session = Depends(get_db),
    _: str = Depends(verify_token)
):
    """Добавление нового домена"""
    # Проверка на существование
    existing = db.query(Domain).filter(Domain.domain == data.domain).first()
    if existing:
        raise HTTPException(status_code=400, detail="Domain already exists")
    
    # Создание записи
    domain = Domain(
        domain=data.domain,
        backend_ip=data.backend_ip,
        backend_port=data.backend_port,
        ssl_mode=data.ssl_mode
    )
    db.add(domain)
    db.commit()
    db.refresh(domain)
    
    # Применение конфигурации HAProxy
    all_domains = db.query(Domain).all()
    success, message = apply_haproxy_config(all_domains)
    
    if not success:
        # Откат при ошибке
        db.delete(domain)
        db.commit()
        raise HTTPException(status_code=500, detail=f"Failed to apply config: {message}")
    
    return DomainResponse(
        id=domain.id,
        domain=domain.domain,
        backend_ip=domain.backend_ip,
        backend_port=domain.backend_port,
        ssl_mode=domain.ssl_mode,
        cert_expiry=None,
        cert_status="missing",
        created_at=domain.created_at
    )


@app.delete("/api/domains/{domain_id}")
async def delete_domain(
    domain_id: int,
    db: Session = Depends(get_db),
    _: str = Depends(verify_token)
):
    """Удаление домена"""
    domain = db.query(Domain).filter(Domain.id == domain_id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    domain_name = domain.domain
    
    # Удаление из БД
    db.delete(domain)
    db.commit()
    
    # Применение конфигурации HAProxy
    all_domains = db.query(Domain).all()
    success, message = apply_haproxy_config(all_domains)
    
    if not success:
        raise HTTPException(status_code=500, detail=f"Failed to apply config: {message}")
    
    # Удаление сертификата
    delete_certificate(domain_name)
    
    return {"status": "ok", "message": f"Domain {domain_name} deleted"}


@app.post("/api/domains/{domain_id}/cert")
async def issue_domain_certificate(
    domain_id: int,
    db: Session = Depends(get_db),
    _: str = Depends(verify_token)
):
    """Выпуск SSL сертификата для домена"""
    domain = db.query(Domain).filter(Domain.id == domain_id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    
    success, message = issue_certificate(domain.domain)
    
    if not success:
        raise HTTPException(status_code=500, detail=f"Failed to issue certificate: {message}")
    
    # Обновление даты истечения
    cert_expiry = get_certificate_expiry(domain.domain)
    if cert_expiry:
        domain.cert_expiry = cert_expiry
        db.commit()
    
    # Перезагрузка HAProxy для применения сертификата
    subprocess.run(["systemctl", "reload", "haproxy"], capture_output=True, timeout=10)
    
    return {"status": "ok", "message": "Certificate issued successfully", "expiry": cert_expiry}


@app.get("/api/health")
async def health_check():
    """Проверка здоровья сервиса"""
    haproxy_status = "unknown"
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "haproxy"],
            capture_output=True,
            text=True,
            timeout=5
        )
        haproxy_status = result.stdout.strip()
    except Exception:
        pass
    
    return {
        "status": "ok",
        "haproxy": haproxy_status,
        "timestamp": datetime.utcnow().isoformat()
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
