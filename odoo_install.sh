#!/bin/bash

# Script de instalación Odoo 19 - Versión actualizada
# Compatible con Ubuntu 20.04+ / Debian 11+
# Actualizado para requisitos Odoo 19.0

# Detener script al primer error
set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variables de configuración
OE_VERSION="19.0"
OE_USER="odoo"
OE_HOME="/opt/$OE_USER"
OE_HOME_EXT="$OE_HOME/$OE_VERSION"
OE_CONFIG="${OE_USER}${OE_VERSION%.*}"  # Combina usuario y versión sin ".0"
OE_PORT="8069"
LONGPOLLING_PORT="8072"

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}    INSTALADOR ODOO 19.0 - VERSIÓN ACTUALIZADA${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

# Verificar que se ejecute como root o con sudo
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Este script debe ejecutarse como root o con sudo${NC}"
   exit 1
fi

# Verificar distribución del sistema
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS=$NAME
    VERSION=$VERSION_ID
else
    echo -e "${RED}No se puede determinar la distribución del sistema${NC}"
    exit 1
fi

echo -e "${GREEN}Sistema detectado: $OS $VERSION${NC}"

# Verificar Python 3.11+
echo -e "${YELLOW}Verificando versión de Python...${NC}"
if python3 -c "import sys; exit(0 if sys.version_info >= (3,11) else 1)" 2>/dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    echo -e "${GREEN}Python $PYTHON_VERSION detectado: OK${NC}"
else
    echo -e "${YELLOW}Python 3.11+ requerido para Odoo 19. Instalando...${NC}"
    add-apt-repository ppa:deadsnakes/ppa -y
    apt update
    apt install -y python3.11 python3.11-venv python3.11-dev python3.11-distutils python3.11-pip
    
    # Crear enlaces simbólicos
    update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1
    
    # Verificar instalación
    if python3 -c "import sys; exit(0 if sys.version_info >= (3,11) else 1)" 2>/dev/null; then
        echo -e "${GREEN}Python 3.11+ instalado correctamente${NC}"
    else
        echo -e "${RED}Error: No se pudo instalar Python 3.11+${NC}"
        exit 1
    fi
fi

# Preguntar por el dominio o subdominio para Nginx
read -p "Introduce el nombre del sitio web para acceder a Odoo (ejemplo: tusitio.com): " WEBSITE_NAME

# Preguntar por el email para Certbot
read -p "Introduce un email válido para Certbot (para notificaciones de renovación): " ADMIN_EMAIL

# Verificar si el usuario ya existe, si no, crearlo
echo -e "${YELLOW}Configurando usuario del sistema...${NC}"
if getent passwd "$OE_USER" > /dev/null 2>&1; then
    echo -e "${GREEN}El usuario $OE_USER ya existe.${NC}"
else
    echo -e "${YELLOW}Creando el usuario $OE_USER...${NC}"
    adduser --system --quiet --shell=/bin/bash --home=$OE_HOME --gecos 'ODOO' --group $OE_USER
    # El usuario debe ser añadido a la lista de sudoers.
    adduser $OE_USER sudo
    echo -e "${GREEN}Usuario $OE_USER creado.${NC}"
fi

# Actualizar el sistema
echo -e "${YELLOW}Actualizando el sistema...${NC}"
apt update && apt upgrade -y

# Instalar dependencias actualizadas para Odoo 19
echo -e "${YELLOW}Instalando dependencias para Odoo 19...${NC}"
apt install -y git python3-cffi build-essential wget curl python3-dev python3-venv \
python3-wheel libxslt-dev libzip-dev libldap2-dev libsasl2-dev python3-setuptools \
node-less libpng-dev libjpeg-dev gdebi libssl-dev libffi-dev libblas-dev \
libatlas-base-dev xfonts-75dpi fontconfig xfonts-base libxrender1 libfontconfig1 \
libx11-dev libjpeg62 libxtst6 libjpeg-turbo8-dev libx11-doc libpq-dev libxcb-doc \
ttf-mscorefonts-installer python3-babel python3-chardet python3-cryptography \
python3-dateutil python3-decorator python3-docutils python3-feedparser \
python3-gevent python3-greenlet python3-html2text python3-jinja2 python3-lxml \
python3-markupsafe python3-num2words python3-ofxparse python3-passlib \
python3-pil python3-polib python3-psutil python3-pydot python3-pyparsing \
python3-qrcode python3-reportlab python3-requests python3-suds python3-tz \
python3-usb python3-werkzeug python3-xlsxwriter python3-zeep python3-xlrd \
python3-openpyxl libevent-dev libxml2-dev libxmlsec1-dev pkg-config

# Instalar Node.js 18+ (requerido para Odoo 19)
echo -e "${YELLOW}Instalando Node.js 18+ (requerido para Odoo 19)...${NC}"
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt-get install -y nodejs

# Verificar versión de Node.js
node_version=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
if [[ $node_version -lt 16 ]]; then
    echo -e "${RED}ERROR: Odoo 19 requiere Node.js 16+. Versión actual: $node_version${NC}"
    exit 1
fi

echo -e "${GREEN}Node.js $(node --version) instalado correctamente${NC}"

# Instalar paquetes NPM con versiones específicas para Odoo 19
echo -e "${YELLOW}Instalando paquetes NPM para Odoo 19...${NC}"
npm install -g less@4.1.3 less-plugin-clean-css@1.5.1 rtlcss@4.1.1

# Crear enlace simbólico para node.js si es necesario
if ! which node > /dev/null; then
    echo -e "${YELLOW}Creando enlace simbólico para Node.js...${NC}"
    ln -s /usr/bin/nodejs /usr/bin/node
fi

# Configuración de PostgreSQL optimizada para Odoo 19
echo -e "${YELLOW}Configurando PostgreSQL optimizado para Odoo 19...${NC}"
apt install -y postgresql postgresql-client postgresql-contrib

# Preguntar por la contraseña de la base de datos
read -p "¿Deseas definir una contraseña para PostgreSQL o generarla automáticamente? (d/g): " DB_PASSWORD_OPTION
if [[ "$DB_PASSWORD_OPTION" =~ ^[Dd]$ ]]; then
    read -sp "Introduce la contraseña para PostgreSQL: " OE_DB_PASSWORD
    echo ""
else
    OE_DB_PASSWORD=$(openssl rand -hex 16)
    echo -e "${GREEN}Contraseña generada para PostgreSQL: $OE_DB_PASSWORD${NC}"
fi

# Crear usuario PostgreSQL
su - postgres -c "psql -c \"CREATE USER $OE_USER WITH CREATEDB SUPERUSER PASSWORD '$OE_DB_PASSWORD';\""

# Optimizaciones PostgreSQL para Odoo 19
PG_VERSION=$(ls /etc/postgresql/)
tee -a /etc/postgresql/$PG_VERSION/main/postgresql.conf > /dev/null <<EOF

# Optimizaciones para Odoo 19
max_connections = 200
shared_buffers = 256MB
effective_cache_size = 1GB
maintenance_work_mem = 64MB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
effective_io_concurrency = 200
work_mem = 4MB
min_wal_size = 1GB
max_wal_size = 4GB
wal_compression = on
log_min_duration_statement = 1000
EOF

systemctl restart postgresql

echo -e "${GREEN}PostgreSQL configurado y optimizado para Odoo 19${NC}"

# Clonar el repositorio de Odoo 19
echo -e "${YELLOW}Clonando repositorio Odoo 19.0...${NC}"
git clone --depth 1 --branch $OE_VERSION https://github.com/odoo/odoo.git $OE_HOME_EXT

# Configurar Enterprise (si aplica)
read -p "¿Tienes acceso al repositorio de GitHub Enterprise de Odoo? (s/n): " INSTALL_ENTERPRISE
if [[ "$INSTALL_ENTERPRISE" =~ ^[Ss]$ ]]; then
    read -p "Introduce tu usuario de GitHub: " GITHUB_USER
    read -sp "Introduce tu contraseña o token de GitHub: " GITHUB_PASS
    echo ""
    echo -e "${YELLOW}Clonando repositorio Enterprise...${NC}"
    git clone --depth 1 --branch $OE_VERSION https://$GITHUB_USER:$GITHUB_PASS@github.com/odoo/enterprise.git $OE_HOME_EXT/enterprise
else
    read -p "¿Tienes archivos Enterprise locales? Introduce la ruta (o presiona Enter para omitir): " ENTERPRISE_PATH
    if [[ -n "$ENTERPRISE_PATH" && -d "$ENTERPRISE_PATH" ]]; then
        echo -e "${YELLOW}Copiando archivos Enterprise desde $ENTERPRISE_PATH...${NC}"
        cp -r $ENTERPRISE_PATH $OE_HOME_EXT/enterprise
    fi
fi

# Crear carpetas necesarias
echo -e "${YELLOW}Creando directorios para Odoo 19...${NC}"
mkdir -p $OE_HOME_EXT/enterprise $OE_HOME_EXT/addons $OE_HOME_EXT/custom/addons
mkdir -p $OE_HOME/.local/share/Odoo
mkdir -p /var/log/$OE_USER

# Establecer permisos
chown -R $OE_USER:$OE_USER $OE_HOME/
chmod -R 755 $OE_HOME_EXT

# Instalar wkhtmltopdf actualizado para Odoo 19
echo -e "${YELLOW}Instalando wkhtmltopdf actualizado...${NC}"
WKHTMLTOX_URL="https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-2/wkhtmltox_0.12.6.1-2.jammy_amd64.deb"
wget $WKHTMLTOX_URL -O wkhtmltox.deb
dpkg -i wkhtmltox.deb || apt-get install -f -y
rm -f wkhtmltox.deb

# Crear enlaces simbólicos para wkhtmltopdf
ln -sf /usr/local/bin/wkhtmltopdf /usr/bin/wkhtmltopdf
ln -sf /usr/local/bin/wkhtmltoimage /usr/bin/wkhtmltoimage
chown $OE_USER:$OE_USER /usr/local/bin/wkhtmltopdf /usr/local/bin/wkhtmltoimage

# Crear entorno virtual con Python 3.11+
echo -e "${YELLOW}Creando entorno virtual para Odoo 19...${NC}"

su $OE_USER -c "
    echo 'Creando entorno virtual para Odoo 19...'
    python3 -m venv $OE_HOME_EXT/venv
    if [[ -d \"$OE_HOME_EXT/venv\" ]]; then
        echo 'Activando entorno virtual...'
        source $OE_HOME_EXT/venv/bin/activate || { echo 'No se pudo activar el entorno virtual.'; exit 1; }
        
        echo 'Actualizando pip, setuptools y wheel...'
        pip install --upgrade pip setuptools wheel || { echo 'Error al actualizar pip.'; exit 1; }
        
        # Instalar dependencias específicas para Odoo 19
        echo 'Instalando dependencias Python para Odoo 19...'
        pip install psycopg2-binary
        pip install pycryptodome
        pip install babel
        pip install python-ldap
        
        # Instalar requirements de Odoo 19
        echo 'Instalando requirements de Odoo 19...'
        pip install -r $OE_HOME_EXT/requirements.txt
        
        # Verificar instalaciones críticas
        python3 -c \"import psycopg2, cryptography, babel\" || { echo 'Error en dependencias críticas'; exit 1; }
        
        deactivate
        echo 'Entorno virtual configurado correctamente'
    else
        echo 'Error: No se pudo crear el entorno virtual'
        exit 1
    fi
"

if [[ $? -ne 0 ]]; then
    echo -e "${RED}Error configurando el entorno virtual${NC}"
    exit 1
fi

echo -e "${GREEN}Entorno virtual de Odoo 19 creado exitosamente${NC}"

# Instalar NGINX y Certbot
echo -e "${YELLOW}Instalando NGINX y Certbot...${NC}"
apt install -y nginx certbot python3-certbot-nginx

# Crear configuración inicial HTTP para Nginx
cat <<EOF > /tmp/odoo_http
server {
    listen 80;
    server_name $WEBSITE_NAME;
    
    # Evitar timeout en requests largos
    client_max_body_size 100M;
    proxy_connect_timeout 3600s;
    proxy_send_timeout 3600s;
    proxy_read_timeout 3600s;
    
    location / {
        proxy_pass http://127.0.0.1:$OE_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_redirect off;
    }
    
    # WebSocket para longpolling
    location /longpolling {
        proxy_pass http://127.0.0.1:$LONGPOLLING_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_redirect off;
    }
}
EOF

# Remover configuraciones existentes si existen
if [ -f /etc/nginx/sites-available/$WEBSITE_NAME ]; then
    echo -e "${YELLOW}Removiendo configuración nginx existente...${NC}"
    rm -f /etc/nginx/sites-available/$WEBSITE_NAME
    rm -f /etc/nginx/sites-enabled/$WEBSITE_NAME
fi

# Aplicar configuración HTTP inicial
mv /tmp/odoo_http /etc/nginx/sites-available/$WEBSITE_NAME
ln -s /etc/nginx/sites-available/$WEBSITE_NAME /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Verificar configuración nginx
nginx -t
if [[ $? -eq 0 ]]; then
    systemctl restart nginx
    echo -e "${GREEN}Nginx configurado correctamente${NC}"
else
    echo -e "${RED}Error en configuración nginx${NC}"
    exit 1
fi

# Configurar archivo de configuración Odoo 19
echo -e "${YELLOW}Creando archivo de configuración Odoo 19...${NC}"
mkdir -p /etc/$OE_USER

tee /etc/$OE_USER/$OE_CONFIG.conf > /dev/null <<EOF
[options]
addons_path = $OE_HOME_EXT/enterprise/addons,$OE_HOME_EXT/addons,$OE_HOME_EXT/custom/addons
admin_passwd = admin
db_host = False
db_port = False
db_user = $OE_USER
db_password = $OE_DB_PASSWORD
xmlrpc_port = $OE_PORT
longpolling_port = $LONGPOLLING_PORT
proxy_mode = True
logfile = /var/log/$OE_USER/$OE_USER.log

# Configuraciones optimizadas para Odoo 19
max_cron_threads = 2
limit_memory_hard = 2684354560
limit_memory_soft = 2147483648
limit_request = 8192
limit_time_cpu = 600
limit_time_real = 1200
limit_time_real_cron = 3600
workers = 0
data_dir = $OE_HOME/.local/share/Odoo

# Seguridad mejorada
list_db = False
db_name = False
without_demo = all

# Logs mejorados
log_level = info
log_handler = :INFO
log_db = False

# Performance
db_maxconn = 64
EOF

chown $OE_USER:$OE_USER /etc/$OE_USER/$OE_CONFIG.conf
chmod 640 /etc/$OE_USER/$OE_CONFIG.conf

# Crear servicio systemd optimizado para Odoo 19
echo -e "${YELLOW}Creando servicio systemd para Odoo 19...${NC}"
tee /etc/systemd/system/$OE_CONFIG.service > /dev/null <<EOF
[Unit]
Description=Odoo $OE_VERSION
Documentation=https://www.odoo.com/documentation/19.0/
Requires=postgresql.service
After=network.target postgresql.service

[Service]
Type=notify
User=$OE_USER
Group=$OE_USER
ExecStart=$OE_HOME_EXT/venv/bin/python3 $OE_HOME_EXT/odoo-bin -c /etc/$OE_USER/$OE_CONFIG.conf
ExecReload=/bin/kill -s HUP \$MAINPID
KillMode=mixed
StandardOutput=journal+console
StandardError=journal
SyslogIdentifier=$OE_CONFIG
Restart=on-failure
RestartSec=10
RestartPreventExitStatus=0

# Límites de recursos para Odoo 19
LimitNOFILE=65535
LimitMEMLOCK=infinity
LimitNPROC=8192

# Variables de entorno
Environment=PATH=$OE_HOME_EXT/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
WorkingDirectory=$OE_HOME_EXT

[Install]
WantedBy=multi-user.target
EOF

# Iniciar servicios
systemctl daemon-reload
systemctl enable $OE_CONFIG.service
systemctl start $OE_CONFIG.service

# Esperar que Odoo inicie
echo -e "${YELLOW}Esperando que Odoo 19 inicie...${NC}"
sleep 10

# Verificar que Odoo esté ejecutándose
if systemctl is-active --quiet $OE_CONFIG.service; then
    echo -e "${GREEN}Odoo 19 iniciado correctamente${NC}"
else
    echo -e "${RED}Error: Odoo no pudo iniciarse. Verificando logs...${NC}"
    journalctl -u $OE_CONFIG.service --no-pager -n 20
    exit 1
fi

# Configurar Certbot para HTTPS
echo -e "${YELLOW}Configurando HTTPS con Certbot...${NC}"
echo "Asegúrate de que $WEBSITE_NAME está configurado correctamente y apunta a este servidor."
read -p "¿Continuar con la configuración de HTTPS? (s/n): " CONTINUE_HTTPS

if [[ "$CONTINUE_HTTPS" =~ ^[Ss]$ ]]; then
    echo -e "${YELLOW}Ejecutando Certbot para HTTPS...${NC}"
    certbot --nginx -d $WEBSITE_NAME --noninteractive --agree-tos --email $ADMIN_EMAIL
    
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}HTTPS configurado correctamente${NC}"
        
        # Actualizar configuración a HTTPS completa optimizada para Odoo 19
        echo -e "${YELLOW}Actualizando configuración Nginx para HTTPS optimizada...${NC}"
        cat <<EOF > /tmp/odoo_https
#odoo server
upstream odoo {
  server 127.0.0.1:$OE_PORT;
}
upstream odoochat {
  server 127.0.0.1:$LONGPOLLING_PORT;
}

# Rate limiting
limit_req_zone \$binary_remote_addr zone=odoo_limit:10m rate=10r/s;

# http -> https
server {
  listen 80;
  server_name $WEBSITE_NAME;
  return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $WEBSITE_NAME;
    
    # Timeouts optimizados para Odoo 19
    proxy_read_timeout 3600s;
    proxy_connect_timeout 3600s;
    proxy_send_timeout 3600s;
    
    # Tamaño máximo de carga
    client_max_body_size 100M;

    # SSL parameters (gestionado por Certbot)
    ssl_certificate /etc/letsencrypt/live/$WEBSITE_NAME/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$WEBSITE_NAME/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    # Logs
    access_log /var/log/nginx/$OE_USER-access.log;
    error_log /var/log/nginx/$OE_USER-error.log;

    # Security headers mejoradas
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Rate limiting
    limit_req zone=odoo_limit burst=20 nodelay;

    # Redirect requests to odoo backend server
    location / {
        proxy_set_header X-Forwarded-Host \$http_host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_redirect off;
        proxy_pass http://odoo;
        
        # Cookies seguras para Odoo 19
        proxy_cookie_flags ~ secure samesite=strict;
    }

    # WebSocket/longpolling para Odoo 19
    location /websocket {
        proxy_pass http://odoochat;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Forwarded-Host \$http_host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_cookie_flags ~ secure samesite=strict;
    }
    
    # Longpolling alternativo
    location /longpolling {
        proxy_pass http://odoochat;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Forwarded-Host \$http_host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_cookie_flags ~ secure samesite=strict;
    }

    # Servir archivos estáticos directamente
    location ~* ^/[^/]+/static/.*\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)\$ {
        root $OE_HOME_EXT;
        try_files /enterprise/addons\$uri /addons\$uri /custom/addons\$uri =404;
        expires 30d;
        add_header Cache-Control "public, immutable";
        access_log off;
    }

    # Archivos de filestore
    location /web/filestore {
        internal;
        alias $OE_HOME/.local/share/Odoo/filestore;
        expires 24h;
    }

    # Compresión mejorada
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/javascript
        application/xml+rss
        application/json
        image/svg+xml;
}
EOF

        # Aplicar nueva configuración HTTPS
        rm -f /etc/nginx/sites-available/$WEBSITE_NAME
        rm -f /etc/nginx/sites-enabled/$WEBSITE_NAME
        
        mv /tmp/odoo_https /etc/nginx/sites-available/$WEBSITE_NAME
        ln -s /etc/nginx/sites-available/$WEBSITE_NAME /etc/nginx/sites-enabled/
        
        nginx -t && systemctl reload nginx
        echo -e "${GREEN}Configuración HTTPS optimizada aplicada${NC}"
        
    else
        echo -e "${YELLOW}Certbot falló, pero puedes configurar HTTPS manualmente más tarde${NC}"
    fi
fi

# Configurar Fail2Ban actualizado para Odoo 19
echo -e "${YELLOW}Configurando Fail2Ban para Odoo 19...${NC}"
apt install -y fail2ban

# Filtro actualizado para logs de Odoo 19
bash -c "cat > /etc/fail2ban/filter.d/odoo-login.conf <<EOF
[Definition]
failregex = ^ \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} \d+ WARNING \S+ \S+ odoo.http: Login failed for db:\S+ login:\S+ from <HOST>
            ^ \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} \d+ INFO \S+ \S+ Login failed for db:\S+ login:\S+ from <HOST>
ignoreregex =
EOF"

# Jail para Odoo 19
bash -c "cat > /etc/fail2ban/jail.d/odoo-login.conf <<EOF
[odoo-login]
enabled = true
port = http,https
bantime = 1800  ; 30 min ban
maxretry = 5    ; if 5 attempts
findtime = 300  ; within 5 min
logpath = /var/log/$OE_USER/$OE_USER.log
filter = odoo-login
action = iptables-multiport[name=odoo, port=\"http,https\"]
EOF"

systemctl enable fail2ban
systemctl restart fail2ban

# Configurar GeoLite2 para funciones de geolocalización
echo -e "${YELLOW}Configurando GeoLite2 para Odoo 19...${NC}"
mkdir -p /usr/share/GeoIP

# Descargar desde fuente alternativa confiable
curl -L -o /tmp/GeoLite2-City.tar.gz "https://github.com/GitSquared/node-geolite2-redist/raw/master/redist/GeoLite2-City.tar.gz"
curl -L -o /tmp/GeoLite2-Country.tar.gz "https://github.com/GitSquared/node-geolite2-redist/raw/master/redist/GeoLite2-Country.tar.gz"

# Extraer archivos
cd /tmp
tar -xzf GeoLite2-City.tar.gz
tar -xzf GeoLite2-Country.tar.gz

# Mover archivos .mmdb
find . -name "*.mmdb" -exec mv {} /usr/share/GeoIP/ \;
chmod -R 755 /usr/share/GeoIP/

# Limpiar archivos temporales
rm -rf /tmp/GeoLite2-*

echo -e "${GREEN}GeoLite2 configurado correctamente${NC}"

# Configuración SSH opcional
read -p "¿Deseas habilitar el acceso SSH para el usuario $OE_USER? (s/n): " ENABLE_SSH
if [[ "$ENABLE_SSH" =~ ^[Ss]$ ]]; then
    echo -e "${YELLOW}Configurando acceso SSH para $OE_USER...${NC}"
    
    # Establecer contraseña
    echo "Establece una contraseña para el usuario $OE_USER:"
    passwd $OE_USER

    # Configurar SSH
    mkdir -p $OE_HOME/.ssh
    chmod 700 $OE_HOME/.ssh
    touch $OE_HOME/.ssh/authorized_keys
    chmod 600 $OE_HOME/.ssh/authorized_keys
    chown -R $OE_USER:$OE_USER $OE_HOME/.ssh

    echo -e "${GREEN}SSH configurado. Puedes agregar claves públicas a $OE_HOME/.ssh/authorized_keys${NC}"
fi

# Verificación final del sistema
echo -e "${YELLOW}Realizando verificaciones finales del sistema...${NC}"

# Verificar servicios
services_ok=true

if systemctl is-active --quiet postgresql; then
    echo -e "${GREEN}✓ PostgreSQL: Activo${NC}"
else
    echo -e "${RED}✗ PostgreSQL: Inactivo${NC}"
    services_ok=false
fi

if systemctl is-active --quiet nginx; then
    echo -e "${GREEN}✓ Nginx: Activo${NC}"
else
    echo -e "${RED}✗ Nginx: Inactivo${NC}"
    services_ok=false
fi

if systemctl is-active --quiet $OE_CONFIG.service; then
    echo -e "${GREEN}✓ Odoo 19: Activo${NC}"
else
    echo -e "${RED}✗ Odoo 19: Inactivo${NC}"
    services_ok=false
fi

if systemctl is-active --quiet fail2ban; then
    echo -e "${GREEN}✓ Fail2Ban: Activo${NC}"
else
    echo -e "${RED}✗ Fail2Ban: Inactivo${NC}"
    services_ok=false
fi

# Verificar conectividad Odoo
sleep 5
if curl -s -o /dev/null -w "%{http_code}" http://localhost:$OE_PORT | grep -q "200\|302\|303"; then
    echo -e "${GREEN}✓ Odoo responde correctamente en puerto $OE_PORT${NC}"
else
    echo -e "${YELLOW}⚠ Odoo puede estar iniciando aún. Verificar manualmente.${NC}"
fi

# Verificar archivos críticos
if [[ -f "/etc/$OE_USER/$OE_CONFIG.conf" ]]; then
    echo -e "${GREEN}✓ Archivo configuración Odoo: OK${NC}"
else
    echo -e "${RED}✗ Archivo configuración Odoo: Faltante${NC}"
    services_ok=false
fi

if [[ -d "$OE_HOME_EXT/venv" ]]; then
    echo -e "${GREEN}✓ Entorno virtual Python: OK${NC}"
else
    echo -e "${RED}✗ Entorno virtual Python: Faltante${NC}"
    services_ok=false
fi

# Verificar logs
if [[ -f "/var/log/$OE_USER/$OE_USER.log" ]]; then
    echo -e "${GREEN}✓ Logs de Odoo: Configurados${NC}"
else
    echo -e "${YELLOW}⚠ Logs de Odoo: Se crearán al iniciar${NC}"
fi

# Crear script de utilidades para administración
echo -e "${YELLOW}Creando script de utilidades...${NC}"
cat > /usr/local/bin/odoo-admin << 'EOF'
#!/bin/bash

# Script de administración Odoo 19
OE_USER="odoo"
OE_VERSION="19.0"
OE_CONFIG="odoo19"
OE_HOME="/opt/$OE_USER"
OE_HOME_EXT="$OE_HOME/$OE_VERSION"

case "$1" in
    start)
        echo "Iniciando Odoo 19..."
        systemctl start $OE_CONFIG.service
        ;;
    stop)
        echo "Deteniendo Odoo 19..."
        systemctl stop $OE_CONFIG.service
        ;;
    restart)
        echo "Reiniciando Odoo 19..."
        systemctl restart $OE_CONFIG.service
        ;;
    status)
        echo "Estado de servicios Odoo:"
        systemctl status $OE_CONFIG.service --no-pager -l
        ;;
    logs)
        echo "Logs de Odoo (últimas 50 líneas):"
        journalctl -u $OE_CONFIG.service -n 50 --no-pager
        ;;
    tail)
        echo "Siguiendo logs de Odoo (Ctrl+C para salir):"
        journalctl -u $OE_CONFIG.service -f
        ;;
    update)
        echo "Actualizando Odoo 19..."
        systemctl stop $OE_CONFIG.service
        cd $OE_HOME_EXT
        sudo -u $OE_USER git pull origin 19.0
        sudo -u $OE_USER $OE_HOME_EXT/venv/bin/pip install --upgrade -r requirements.txt
        systemctl start $OE_CONFIG.service
        echo "Actualización completada"
        ;;
    backup-db)
        if [[ -z "$2" ]]; then
            echo "Uso: odoo-admin backup-db nombre_bd"
            exit 1
        fi
        echo "Creando backup de base de datos $2..."
        sudo -u postgres pg_dump $2 > "/tmp/odoo_backup_$2_$(date +%Y%m%d_%H%M%S).sql"
        echo "Backup creado en /tmp/"
        ;;
    config)
        echo "Editando configuración Odoo:"
        nano /etc/$OE_USER/$OE_CONFIG.conf
        echo "Reinicia Odoo para aplicar cambios: odoo-admin restart"
        ;;
    addons)
        echo "Carpetas de addons:"
        echo "Enterprise: $OE_HOME_EXT/enterprise/addons"
        echo "Community: $OE_HOME_EXT/addons"
        echo "Custom: $OE_HOME_EXT/custom/addons"
        ;;
    info)
        echo "=== INFORMACIÓN DEL SISTEMA ODOO 19 ==="
        echo "Usuario: $OE_USER"
        echo "Directorio: $OE_HOME_EXT"
        echo "Configuración: /etc/$OE_USER/$OE_CONFIG.conf"
        echo "Logs: /var/log/$OE_USER/$OE_USER.log"
        echo "Servicio: $OE_CONFIG.service"
        echo "Puerto: $(grep xmlrpc_port /etc/$OE_USER/$OE_CONFIG.conf | cut -d' ' -f3)"
        echo "Estado: $(systemctl is-active $OE_CONFIG.service)"
        ;;
    *)
        echo "Script de administración Odoo 19"
        echo ""
        echo "Uso: odoo-admin [comando]"
        echo ""
        echo "Comandos disponibles:"
        echo "  start       - Iniciar Odoo"
        echo "  stop        - Detener Odoo"
        echo "  restart     - Reiniciar Odoo"
        echo "  status      - Ver estado del servicio"
        echo "  logs        - Ver logs recientes"
        echo "  tail        - Seguir logs en tiempo real"
        echo "  update      - Actualizar Odoo desde Git"
        echo "  backup-db   - Crear backup de base de datos"
        echo "  config      - Editar configuración"
        echo "  addons      - Mostrar rutas de addons"
        echo "  info        - Información del sistema"
        ;;
esac
EOF

chmod +x /usr/local/bin/odoo-admin

# Crear script de monitoreo
cat > /usr/local/bin/odoo-monitor << 'EOF'
#!/bin/bash

# Monitor de salud Odoo 19
OE_CONFIG="odoo19"
OE_PORT="8069"

echo "=== MONITOR DE SALUD ODOO 19 ==="
echo "Fecha: $(date)"
echo ""

# Estado del servicio
echo "1. Estado del servicio:"
if systemctl is-active --quiet $OE_CONFIG.service; then
    echo "   ✓ Odoo está ejecutándose"
else
    echo "   ✗ Odoo NO está ejecutándose"
fi

# Conectividad HTTP
echo ""
echo "2. Conectividad HTTP:"
response=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 10 http://localhost:$OE_PORT 2>/dev/null || echo "000")
if [[ "$response" =~ ^(200|302|303)$ ]]; then
    echo "   ✓ HTTP responde correctamente (código: $response)"
else
    echo "   ✗ HTTP no responde o error (código: $response)"
fi

# Uso de memoria
echo ""
echo "3. Uso de recursos:"
if pgrep -f "odoo-bin" > /dev/null; then
    memory_mb=$(ps -o pid,rss,cmd -C python3 | grep odoo-bin | awk '{sum+=$2} END {print sum/1024}')
    echo "   Memoria RAM: ${memory_mb:-0} MB"
    
    cpu_usage=$(ps -o pid,pcpu,cmd -C python3 | grep odoo-bin | awk '{sum+=$2} END {print sum}')
    echo "   Uso CPU: ${cpu_usage:-0}%"
else
    echo "   Proceso Odoo no encontrado"
fi

# Estado PostgreSQL
echo ""
echo "4. Base de datos:"
if systemctl is-active --quiet postgresql; then
    echo "   ✓ PostgreSQL activo"
    connections=$(sudo -u postgres psql -t -c "SELECT count(*) FROM pg_stat_activity WHERE datname IS NOT NULL;" 2>/dev/null | xargs)
    echo "   Conexiones activas: ${connections:-'N/A'}"
else
    echo "   ✗ PostgreSQL inactivo"
fi

# Logs recientes de error
echo ""
echo "5. Errores recientes (últimas 24 horas):"
error_count=$(journalctl -u $OE_CONFIG.service --since "24 hours ago" --no-pager -q | grep -i "error\|exception\|traceback" | wc -l)
if [[ $error_count -eq 0 ]]; then
    echo "   ✓ Sin errores detectados"
else
    echo "   ⚠ $error_count errores encontrados"
    echo "   Ejecuta: journalctl -u $OE_CONFIG.service --since '24 hours ago' | grep -i error"
fi

# Espacio en disco
echo ""
echo "6. Espacio en disco:"
disk_usage=$(df -h / | tail -1 | awk '{print $5}')
echo "   Uso del disco: $disk_usage"

echo ""
echo "=== FIN DEL REPORTE ==="
EOF

chmod +x /usr/local/bin/odoo-monitor

# Crear tarea cron para backup automático (opcional)
read -p "¿Deseas configurar backups automáticos diarios? (s/n): " SETUP_BACKUP
if [[ "$SETUP_BACKUP" =~ ^[Ss]$ ]]; then
    mkdir -p /opt/odoo-backups
    chown $OE_USER:$OE_USER /opt/odoo-backups
    
    cat > /usr/local/bin/odoo-backup-auto << 'EOF'
#!/bin/bash
# Backup automático de Odoo 19

BACKUP_DIR="/opt/odoo-backups"
DATE=$(date +%Y%m%d_%H%M%S)
OE_USER="odoo"

# Crear directorio si no existe
mkdir -p $BACKUP_DIR

# Backup de filestore
echo "Backing up filestore..."
tar -czf $BACKUP_DIR/filestore_$DATE.tar.gz -C /opt/$OE_USER/.local/share/Odoo filestore/ 2>/dev/null || echo "No filestore found"

# Backup de custom addons
echo "Backing up custom addons..."
tar -czf $BACKUP_DIR/custom_addons_$DATE.tar.gz -C /opt/$OE_USER/19.0 custom/ 2>/dev/null || echo "No custom addons found"

# Backup de configuración
echo "Backing up configuration..."
cp /etc/$OE_USER/odoo19.conf $BACKUP_DIR/config_$DATE.conf

# Limpiar backups antiguos (más de 7 días)
find $BACKUP_DIR -type f -mtime +7 -delete

echo "Backup completed: $DATE"
EOF

    chmod +x /usr/local/bin/odoo-backup-auto
    
    # Agregar a crontab
    (crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/odoo-backup-auto >> /var/log/odoo-backup.log 2>&1") | crontab -
    
    echo -e "${GREEN}✓ Backup automático configurado (diario a las 2:00 AM)${NC}"
fi

# Resumen final de la instalación
echo ""
echo -e "${BLUE}================================================================${NC}"
echo -e "${BLUE}           ¡INSTALACIÓN DE ODOO 19 COMPLETADA!${NC}"
echo -e "${BLUE}================================================================${NC}"
echo ""
echo -e "${GREEN}INFORMACIÓN DEL SISTEMA:${NC}"
echo -e "${GREEN}-------------------------${NC}"
echo "✓ Versión Odoo: $OE_VERSION"
echo "✓ Usuario del servicio: $OE_USER"
echo "✓ Puerto principal: $OE_PORT"
echo "✓ Puerto Longpolling: $LONGPOLLING_PORT"
echo "✓ Python: $(python3 --version)"
echo "✓ Node.js: $(node --version)"
echo "✓ PostgreSQL: $(sudo -u postgres psql --version | head -1)"
echo ""
echo -e "${GREEN}UBICACIONES IMPORTANTES:${NC}"
echo -e "${GREEN}-------------------------${NC}"
echo "• Código fuente: $OE_HOME_EXT"
echo "• Configuración: /etc/$OE_USER/$OE_CONFIG.conf"
echo "• Logs: /var/log/$OE_USER/$OE_USER.log"
echo "• Datos: $OE_HOME/.local/share/Odoo"
echo "• Addons personalizados: $OE_HOME_EXT/custom/addons"
echo ""
echo -e "${GREEN}CREDENCIALES:${NC}"
echo -e "${GREEN}-------------${NC}"
echo "• Usuario PostgreSQL: $OE_USER"
echo "• Contraseña PostgreSQL: $OE_DB_PASSWORD"
echo "• Contraseña admin Odoo: admin (cambiar en primera configuración)"
echo ""
echo -e "${GREEN}COMANDOS ÚTILES:${NC}"
echo -e "${GREEN}----------------${NC}"
echo "• Administrar Odoo: odoo-admin [start|stop|restart|status|logs]"
echo "• Monitorear sistema: odoo-monitor"
echo "• Ver logs: journalctl -u $OE_CONFIG.service -f"
echo "• Editar configuración: nano /etc/$OE_USER/$OE_CONFIG.conf"
echo ""
echo -e "${GREEN}ACCESO WEB:${NC}"
echo -e "${GREEN}-----------${NC}"
if [[ "$CONTINUE_HTTPS" =~ ^[Ss]$ ]]; then
    echo "• URL principal: https://$WEBSITE_NAME"
    echo "• URL alternativa: http://$WEBSITE_NAME (redirige a HTTPS)"
else
    echo "• URL principal: http://$WEBSITE_NAME"
    echo "• Configurar HTTPS: certbot --nginx -d $WEBSITE_NAME"
fi
echo ""
echo -e "${GREEN}ADDONS DISPONIBLES:${NC}"
echo -e "${GREEN}-------------------${NC}"
echo "• Community: $OE_HOME_EXT/addons"
if [[ -d "$OE_HOME_EXT/enterprise" ]]; then
    echo "• Enterprise: $OE_HOME_EXT/enterprise/addons"
fi
echo "• Personalizados: $OE_HOME_EXT/custom/addons"
echo ""
echo -e "${YELLOW}PRÓXIMOS PASOS RECOMENDADOS:${NC}"
echo -e "${YELLOW}----------------------------${NC}"
echo "1. Acceder a https://$WEBSITE_NAME y crear la primera base de datos"
echo "2. Cambiar la contraseña del usuario admin"
echo "3. Instalar módulos necesarios para tu proyecto"
echo "4. Configurar copias de seguridad adicionales si es necesario"
echo "5. Revisar logs: odoo-admin logs"
echo ""

if [[ "$services_ok" == true ]]; then
    echo -e "${GREEN}✅ INSTALACIÓN EXITOSA - TODOS LOS SERVICIOS OPERATIVOS${NC}"
    echo -e "${GREEN}Odoo 19 está listo para usar en: http://$WEBSITE_NAME${NC}"
else
    echo -e "${YELLOW}⚠️  INSTALACIÓN COMPLETADA CON ADVERTENCIAS${NC}"
    echo -e "${YELLOW}Revisar servicios inactivos antes de usar${NC}"
fi

echo ""
echo -e "${BLUE}================================================================${NC}"
echo -e "${BLUE}Para soporte: https://www.odoo.com/documentation/19.0/${NC}"
echo -e "${BLUE}================================================================${NC}"
echo ""

# Log de instalación
echo "$(date): Instalación de Odoo 19 completada en $HOSTNAME por $(whoami)" >> /var/log/odoo-install.log

exit 0
