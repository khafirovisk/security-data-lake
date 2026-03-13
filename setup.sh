#!/usr/bin/env bash
# =============================================================================
# Fix rápido — corrige o setup.sh e gera o .env sem depender do .env.example
# Execute: sudo bash fix_setup.sh
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[⚠]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }

echo -e "\n${YELLOW}Security Data Lake — Fix: gerando .env${NC}\n"

if [[ -f "$ENV_FILE" ]]; then
  warn ".env já existe em $ENV_FILE"
  read -rp "Sobrescrever e regenerar segredos? [s/N]: " confirm
  [[ "$confirm" != "s" ]] && { log "Nada alterado."; exit 0; }
  cp "$ENV_FILE" "${ENV_FILE}.bak_$(date +%Y%m%d_%H%M%S)"
  log "Backup salvo em ${ENV_FILE}.bak_*"
fi

log "Gerando segredos criptográficos..."

app_secret=$(openssl rand -hex 32)
jwt_secret=$(openssl rand -hex 32)
airflow_fernet=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>/dev/null \
                 || openssl rand -base64 32 | tr -d '\n/+=')
airflow_secret=$(openssl rand -hex 24)

gen_pw() { openssl rand -base64 "$1" | tr -d '/+=\n' | head -c "$1"; }

if command -v pwgen &>/dev/null; then
  postgres_pw=$(pwgen -s 32 1)
  redis_pw=$(pwgen -s 24 1)
  elastic_pw=$(pwgen -s 24 1)
  vault_token=$(pwgen -s 32 1)
  airflow_admin_pw=$(pwgen -s 20 1)
else
  postgres_pw=$(gen_pw 32)
  redis_pw=$(gen_pw 24)
  elastic_pw=$(gen_pw 24)
  vault_token=$(gen_pw 32)
  airflow_admin_pw=$(gen_pw 20)
fi

log "Escrevendo $ENV_FILE ..."

cat > "$ENV_FILE" << EOF
# ============================================================
# SECURITY DATA LAKE — Gerado automaticamente em $(date)
# ============================================================

# --- Aplicação ---
APP_SECRET_KEY=${app_secret}
APP_ENV=production
APP_HOST=0.0.0.0
APP_PORT=8000
APP_DEBUG=false
FRONTEND_URL=http://localhost

# --- JWT ---
JWT_SECRET_KEY=${jwt_secret}
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=60
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# --- PostgreSQL ---
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_DB=security_data_lake
POSTGRES_USER=sdl_admin
POSTGRES_PASSWORD=${postgres_pw}
DATABASE_URL=postgresql://sdl_admin:${postgres_pw}@postgres:5432/security_data_lake

# --- Elasticsearch ---
ELASTICSEARCH_HOST=elasticsearch
ELASTICSEARCH_PORT=9200
ELASTICSEARCH_USER=elastic
ELASTICSEARCH_PASSWORD=${elastic_pw}

# --- Redis ---
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=${redis_pw}

# --- HashiCorp Vault ---
VAULT_ADDR=http://vault:8200
VAULT_TOKEN=${vault_token}
VAULT_MOUNT_PATH=secret/sdl

# --- Airflow ---
AIRFLOW_FERNET_KEY=${airflow_fernet}
AIRFLOW_SECRET_KEY=${airflow_secret}
AIRFLOW_ADMIN_USER=airflow_admin
AIRFLOW_ADMIN_PASSWORD=${airflow_admin_pw}
AIRFLOW__DATABASE__SQL_ALCHEMY_CONN=postgresql+psycopg2://sdl_admin:${postgres_pw}@postgres:5432/airflow_db

# ============================================================
# API KEYS — configure via: ./scripts/manage.sh secrets set
# ============================================================
SENTINELONE_BASE_URL=
SENTINELONE_API_TOKEN=
QUALYS_BASE_URL=https://qualysapi.qualys.com
QUALYS_USERNAME=
QUALYS_PASSWORD=
PROOFPOINT_BASE_URL=https://tap-api-v2.proofpoint.com
PROOFPOINT_SERVICE_PRINCIPAL=
PROOFPOINT_SECRET=
MANTIS_BASE_URL=https://api.mantis.internal
MANTIS_API_KEY=
CISO_BASE_URL=http://ciso-assistance.internal:8080
CISO_API_KEY=
CISO_VERIFY_SSL=false
MS_TENANT_ID=
MS_CLIENT_ID=
MS_CLIENT_SECRET=
MS_SUBSCRIPTION_ID=
GOOGLE_PROJECT_ID=
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_REGION=us-east-1
FORTIGATE_BASE_URL=http://fortigate.internal/api/v2
FORTIGATE_API_KEY=
FORTIGATE_VERIFY_SSL=false

# --- Pipeline ---
PIPELINE_INTERVAL_MINUTES=60
PIPELINE_BATCH_SIZE=1000
PIPELINE_MAX_RETRIES=3
PIPELINE_TIMEOUT_SECONDS=300
EOF

chmod 600 "$ENV_FILE"
log ".env criado com permissão 600"

# Salva resumo legível
cat > "$SCRIPT_DIR/CREDENTIALS.txt" << EOF
# Security Data Lake — Credenciais geradas em $(date)
# MANTENHA ESTE ARQUIVO SEGURO — não commitar no git!

PostgreSQL Password : ${postgres_pw}
Redis Password      : ${redis_pw}
Elastic Password    : ${elastic_pw}
Vault Token         : ${vault_token}
JWT Secret          : ${jwt_secret}
Airflow Admin User  : airflow_admin
Airflow Admin Pass  : ${airflow_admin_pw}

Para configurar API keys:
  ./scripts/manage.sh secrets set sentinelone/api_token "SUA_KEY"
EOF
chmod 600 "$SCRIPT_DIR/CREDENTIALS.txt"
log "Credenciais salvas em CREDENTIALS.txt"

# Corrige setup.sh para não usar cp .env.example no futuro
if grep -q '\.env\.example' "$SCRIPT_DIR/setup.sh" 2>/dev/null; then
  sed -i 's|cp "\$SCRIPT_DIR/\.env\.example" "\$SCRIPT_DIR/\.env"|echo ".env ja existe, pulando copia"|g' \
      "$SCRIPT_DIR/setup.sh"
  log "setup.sh corrigido (referência a .env.example removida)"
fi

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  .env gerado com sucesso!${NC}"
echo -e "${GREEN}  Agora execute: sudo ./setup.sh${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
