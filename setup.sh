#!/usr/bin/env bash
# =============================================================================
# Security Data Lake — Ubuntu Server Setup Script
# Compatível com Ubuntu 20.04 / 22.04 / 24.04
# Uso: sudo ./setup.sh
# =============================================================================

set -euo pipefail

# ─── Cores ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ─── Variáveis globais ────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SCRIPT_DIR/setup.log"
MIN_RAM_GB=8
MIN_DISK_GB=40
COMPOSE_VERSION="v2.24.5"

# ─── Funções utilitárias ──────────────────────────────────────────────────────
log()     { echo -e "${GREEN}[✓]${NC} $1" | tee -a "$LOG_FILE"; }
warn()    { echo -e "${YELLOW}[⚠]${NC} $1" | tee -a "$LOG_FILE"; }
error()   { echo -e "${RED}[✗]${NC} $1" | tee -a "$LOG_FILE"; exit 1; }
info()    { echo -e "${BLUE}[→]${NC} $1" | tee -a "$LOG_FILE"; }
header()  { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════${NC}"; echo -e "${BOLD}${CYAN}  $1${NC}"; echo -e "${BOLD}${CYAN}══════════════════════════════════════════${NC}\n"; }

banner() {
  echo -e "${BOLD}${CYAN}"
  cat << 'EOF'
  ___  ___  _       ___  ___  _
 / __|| __|| |     |   \  /_\ | |_  __ _   | |    __ _  | |__ ___
 \__ \| _| | |__  | |) |/ _ \|  _|/ _` |  | |__ / _` | | / // -_)
 |___/|___||____| |___//_/ \_\\__|\__,_|  |____|\__,_| |_\_\\___|

         Security Data Lake — Pipeline de Telemetria
         Versão 1.0 | Ubuntu Server Setup
EOF
  echo -e "${NC}"
}

# ─── Verificações de pré-requisitos ──────────────────────────────────────────
check_root() {
  [[ $EUID -eq 0 ]] || error "Este script deve ser executado como root. Use: sudo ./setup.sh"
}

check_os() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    if [[ "$ID" != "ubuntu" ]]; then
      warn "Este script foi testado no Ubuntu. SO atual: $ID"
    fi
    log "Sistema operacional: $PRETTY_NAME"
  fi
}

check_resources() {
  header "Verificando Recursos do Sistema"

  local ram_gb
  ram_gb=$(awk '/MemTotal/{printf "%.0f", $2/1024/1024}' /proc/meminfo)
  if (( ram_gb < MIN_RAM_GB )); then
    warn "RAM disponível: ${ram_gb}GB. Recomendado: ${MIN_RAM_GB}GB mínimo."
  else
    log "RAM: ${ram_gb}GB ✓"
  fi

  local disk_gb
  disk_gb=$(df -BG "$SCRIPT_DIR" | awk 'NR==2{print $4}' | tr -d 'G')
  if (( disk_gb < MIN_DISK_GB )); then
    warn "Espaço em disco livre: ${disk_gb}GB. Recomendado: ${MIN_DISK_GB}GB."
  else
    log "Disco livre: ${disk_gb}GB ✓"
  fi

  local cpu_cores
  cpu_cores=$(nproc)
  log "CPU cores: $cpu_cores"
}

# ─── Instalação de dependências ───────────────────────────────────────────────
install_base_packages() {
  header "Instalando Pacotes Base"
  info "Atualizando repositórios..."
  apt-get update -qq >> "$LOG_FILE" 2>&1

  local packages=(
    curl wget git unzip jq vim htop
    apt-transport-https ca-certificates gnupg lsb-release
    software-properties-common python3 python3-pip python3-venv
    openssl pwgen netcat-openbsd ufw fail2ban
  )

  for pkg in "${packages[@]}"; do
    if dpkg -l "$pkg" &>/dev/null; then
      info "$pkg já instalado"
    else
      apt-get install -y -qq "$pkg" >> "$LOG_FILE" 2>&1
      log "$pkg instalado"
    fi
  done
}

install_docker() {
  header "Instalando Docker"

  if command -v docker &>/dev/null; then
    log "Docker já instalado: $(docker --version)"
    return
  fi

  info "Adicionando repositório oficial Docker..."
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg

  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    tee /etc/apt/sources.list.d/docker.list > /dev/null

  apt-get update -qq >> "$LOG_FILE" 2>&1
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >> "$LOG_FILE" 2>&1

  systemctl enable docker >> "$LOG_FILE" 2>&1
  systemctl start docker

  log "Docker instalado: $(docker --version)"
}

install_docker_compose() {
  header "Instalando Docker Compose"

  if docker compose version &>/dev/null 2>&1; then
    log "Docker Compose plugin já disponível"
    return
  fi

  info "Baixando Docker Compose $COMPOSE_VERSION..."
  local arch
  arch=$(dpkg --print-architecture)
  curl -SL "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-linux-${arch}" \
    -o /usr/local/bin/docker-compose >> "$LOG_FILE" 2>&1
  chmod +x /usr/local/bin/docker-compose
  log "Docker Compose instalado: $(docker-compose --version)"
}

# ─── Configuração do ambiente ─────────────────────────────────────────────────
generate_secrets() {
  header "Gerando Segredos Seguros"

  if [[ -f "$SCRIPT_DIR/.env" ]]; then
    warn "Arquivo .env já existe. Pulando geração de segredos."
    warn "Para regenerar: rm .env && sudo ./setup.sh"
    return
  fi

  info "Gerando chaves criptográficas..."

  local app_secret jwt_secret postgres_pw redis_pw elastic_pw vault_token airflow_fernet airflow_secret
  app_secret=$(openssl rand -hex 32)
  jwt_secret=$(openssl rand -hex 32)
  postgres_pw=$(pwgen -s 32 1)
  redis_pw=$(pwgen -s 24 1)
  elastic_pw=$(pwgen -s 24 1)
  vault_token=$(pwgen -s 32 1)
  airflow_fernet=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>/dev/null || openssl rand -base64 32)
  airflow_secret=$(openssl rand -hex 24)

  cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"

  sed -i "s|CHANGE_THIS_TO_A_RANDOM_SECRET_64_CHARS|$app_secret|g" "$SCRIPT_DIR/.env"
  sed -i "s|CHANGE_THIS_TO_ANOTHER_RANDOM_SECRET|$jwt_secret|g" "$SCRIPT_DIR/.env"
  sed -i "s|CHANGE_THIS_STRONG_PASSWORD|$postgres_pw|g" "$SCRIPT_DIR/.env"
  sed -i "s|CHANGE_THIS_REDIS_PASSWORD|$redis_pw|g" "$SCRIPT_DIR/.env"
  sed -i "s|CHANGE_THIS_ELASTIC_PASSWORD|$elastic_pw|g" "$SCRIPT_DIR/.env"
  sed -i "s|CHANGE_THIS_VAULT_ROOT_TOKEN|$vault_token|g" "$SCRIPT_DIR/.env"
  sed -i "s|CHANGE_THIS_FERNET_KEY_32_BYTES_BASE64|$airflow_fernet|g" "$SCRIPT_DIR/.env"
  sed -i "s|CHANGE_THIS_AIRFLOW_SECRET|$airflow_secret|g" "$SCRIPT_DIR/.env"

  chmod 600 "$SCRIPT_DIR/.env"
  log "Arquivo .env gerado com segredos seguros"

  # Salvar resumo das credenciais (sem incluir no git)
  cat > "$SCRIPT_DIR/CREDENTIALS.txt" << EOF
# Security Data Lake — Credenciais Geradas em $(date)
# MANTENHA ESTE ARQUIVO SEGURO E FORA DO GIT

PostgreSQL Password: $postgres_pw
Redis Password:      $redis_pw
Elastic Password:    $elastic_pw
Vault Token:         $vault_token
JWT Secret:          $jwt_secret

Airflow Admin User: airflow_admin
Airflow Admin Password: (configure em .env -> AIRFLOW_ADMIN_PASSWORD)

Para configurar API keys: ./scripts/manage.sh secrets set <key_name> <value>
EOF
  chmod 600 "$SCRIPT_DIR/CREDENTIALS.txt"
  log "Credenciais salvas em CREDENTIALS.txt (não commitar!)"
}

configure_firewall() {
  header "Configurando Firewall (UFW)"

  ufw --force reset >> "$LOG_FILE" 2>&1
  ufw default deny incoming >> "$LOG_FILE" 2>&1
  ufw default allow outgoing >> "$LOG_FILE" 2>&1

  # SSH
  ufw allow 22/tcp comment "SSH" >> "$LOG_FILE" 2>&1
  # HTTP/HTTPS
  ufw allow 80/tcp comment "HTTP" >> "$LOG_FILE" 2>&1
  ufw allow 443/tcp comment "HTTPS" >> "$LOG_FILE" 2>&1
  # Airflow UI (restringir se necessário)
  ufw allow 8080/tcp comment "Airflow UI" >> "$LOG_FILE" 2>&1
  # Kibana (restringir para rede interna se necessário)
  ufw allow 5601/tcp comment "Kibana" >> "$LOG_FILE" 2>&1

  ufw --force enable >> "$LOG_FILE" 2>&1
  log "Firewall configurado"
  ufw status
}

configure_fail2ban() {
  header "Configurando Fail2Ban"

  cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(syslog_backend)s
EOF

  systemctl enable fail2ban >> "$LOG_FILE" 2>&1
  systemctl restart fail2ban >> "$LOG_FILE" 2>&1
  log "Fail2Ban configurado"
}

setup_nginx_ssl() {
  header "Gerando Certificado SSL Self-Signed"

  mkdir -p "$SCRIPT_DIR/nginx/ssl"
  if [[ ! -f "$SCRIPT_DIR/nginx/ssl/server.crt" ]]; then
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout "$SCRIPT_DIR/nginx/ssl/server.key" \
      -out "$SCRIPT_DIR/nginx/ssl/server.crt" \
      -subj "/C=BR/ST=SP/L=SaoPaulo/O=SecurityDataLake/CN=localhost" \
      >> "$LOG_FILE" 2>&1
    log "Certificado SSL gerado"
  else
    info "Certificado SSL já existe"
  fi
}

setup_user_permissions() {
  header "Configurando Permissões"

  # Criar usuário de serviço se não existir
  if ! id "sdl" &>/dev/null; then
    useradd -r -s /bin/bash -d "$SCRIPT_DIR" sdl
    log "Usuário de serviço 'sdl' criado"
  fi

  # Adicionar usuário atual ao grupo docker
  local current_user="${SUDO_USER:-$USER}"
  if [[ "$current_user" != "root" ]]; then
    usermod -aG docker "$current_user"
    log "Usuário $current_user adicionado ao grupo docker"
    warn "Faça logout/login para aplicar permissões do grupo docker"
  fi

  # Permissões no diretório do projeto
  chown -R "$current_user:$current_user" "$SCRIPT_DIR" 2>/dev/null || true
  chmod +x "$SCRIPT_DIR/scripts/"*.sh 2>/dev/null || true
  chmod 600 "$SCRIPT_DIR/.env" 2>/dev/null || true
}

# ─── Inicialização dos containers ─────────────────────────────────────────────
start_services() {
  header "Iniciando Serviços Docker"

  cd "$SCRIPT_DIR"

  info "Construindo imagens..."
  docker compose build --no-cache >> "$LOG_FILE" 2>&1
  log "Imagens construídas"

  info "Iniciando infraestrutura base (Postgres, Redis, Vault, Elasticsearch)..."
  docker compose up -d postgres redis vault elasticsearch >> "$LOG_FILE" 2>&1
  sleep 10

  info "Inicializando Airflow..."
  docker compose up -d airflow-init >> "$LOG_FILE" 2>&1
  sleep 15

  info "Iniciando todos os serviços..."
  docker compose up -d >> "$LOG_FILE" 2>&1
  sleep 10

  log "Todos os serviços iniciados"
}

create_admin_user() {
  header "Criando Usuário Administrador Inicial"

  local admin_user admin_pass
  echo -e "${YELLOW}Configure o usuário administrador do Security Data Lake:${NC}"
  read -rp "Username [admin]: " admin_user
  admin_user="${admin_user:-admin}"

  while true; do
    read -rsp "Senha (mínimo 12 caracteres): " admin_pass
    echo
    if [[ ${#admin_pass} -ge 12 ]]; then
      break
    fi
    warn "Senha muito curta. Tente novamente."
  done

  # Aguardar backend estar disponível
  info "Aguardando backend estar disponível..."
  local retries=0
  while ! curl -sf http://localhost:8000/health > /dev/null 2>&1; do
    sleep 5
    ((retries++))
    if (( retries > 24 )); then
      warn "Backend não respondeu em tempo. Crie o admin manualmente:"
      warn "  ./scripts/manage.sh user create --username admin --role admin"
      return
    fi
  done

  # Criar admin via CLI
  "$SCRIPT_DIR/scripts/manage.sh" user create \
    --username "$admin_user" \
    --password "$admin_pass" \
    --role admin \
    --email "admin@security-data-lake.local"

  log "Usuário administrador '$admin_user' criado com sucesso"
}

# ─── Verificação final ────────────────────────────────────────────────────────
health_check() {
  header "Verificação de Saúde dos Serviços"

  local services=(
    "Backend API|http://localhost:8000/health"
    "Airflow UI|http://localhost:8080/health"
    "Kibana|http://localhost:5601/api/status"
  )

  for svc in "${services[@]}"; do
    local name url
    name="${svc%%|*}"
    url="${svc##*|}"
    if curl -sf "$url" > /dev/null 2>&1; then
      log "$name — OK"
    else
      warn "$name — Ainda iniciando (pode levar alguns minutos)"
    fi
  done

  info "Status dos containers:"
  docker compose ps
}

print_summary() {
  header "Instalação Concluída!"

  echo -e "${BOLD}${GREEN}"
  cat << EOF
╔══════════════════════════════════════════════════════════╗
║            SECURITY DATA LAKE — ACESSOS                 ║
╠══════════════════════════════════════════════════════════╣
║  🌐  Dashboard:    http://$(hostname -I | awk '{print $1}')                  
║  🔧  API Docs:     http://$(hostname -I | awk '{print $1}'):8000/docs        
║  🌀  Airflow:      http://$(hostname -I | awk '{print $1}'):8080             
║  📊  Kibana:       http://$(hostname -I | awk '{print $1}'):5601             
║  🔐  Vault:        http://$(hostname -I | awk '{print $1}'):8200             
╠══════════════════════════════════════════════════════════╣
║  📄  Credenciais:  ./CREDENTIALS.txt                    ║
║  📋  Logs setup:   ./setup.log                          ║
╠══════════════════════════════════════════════════════════╣
║  PRÓXIMOS PASSOS:                                       ║
║  1. Configure API keys:                                 ║
║     ./scripts/manage.sh secrets set <tool> <key>       ║
║  2. Ative os pipelines no Airflow UI                   ║
║  3. Acesse o Dashboard e explore os KPIs               ║
╚══════════════════════════════════════════════════════════╝
EOF
  echo -e "${NC}"
}

# ─── Setup systemd service (auto-start) ──────────────────────────────────────
install_systemd_service() {
  header "Configurando Auto-Start (systemd)"

  cat > /etc/systemd/system/security-data-lake.service << EOF
[Unit]
Description=Security Data Lake
Requires=docker.service
After=docker.service network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$SCRIPT_DIR
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=300
User=root

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable security-data-lake.service
  log "Serviço systemd configurado — inicia automaticamente no boot"
}

# ─── Entry point ─────────────────────────────────────────────────────────────
main() {
  banner
  echo "Log: $LOG_FILE"
  echo "Iniciado em: $(date)" > "$LOG_FILE"

  check_root
  check_os
  check_resources
  install_base_packages
  install_docker
  install_docker_compose
  generate_secrets
  configure_firewall
  configure_fail2ban
  setup_nginx_ssl
  setup_user_permissions
  start_services
  install_systemd_service
  create_admin_user
  health_check
  print_summary
}

# ─── Parse de argumentos ──────────────────────────────────────────────────────
case "${1:-install}" in
  install)    main ;;
  start)      cd "$SCRIPT_DIR" && docker compose up -d ;;
  stop)       cd "$SCRIPT_DIR" && docker compose down ;;
  restart)    cd "$SCRIPT_DIR" && docker compose restart ;;
  status)     cd "$SCRIPT_DIR" && docker compose ps ;;
  logs)       cd "$SCRIPT_DIR" && docker compose logs -f "${2:-}" ;;
  update)
    cd "$SCRIPT_DIR"
    git pull
    docker compose build --no-cache
    docker compose up -d
    ;;
  *)
    echo "Uso: sudo ./setup.sh [install|start|stop|restart|status|logs|update]"
    exit 1
    ;;
esac
