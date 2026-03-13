#!/usr/bin/env bash
# =============================================================================
# Security Data Lake — Management CLI
# Uso: ./scripts/manage.sh <command> [options]
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_URL="${BACKEND_URL:-http://localhost:8000}"
TOKEN_FILE="${HOME}/.sdl_token"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

log()   { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${YELLOW}[⚠]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; exit 1; }
info()  { echo -e "${BLUE}[→]${NC} $1"; }

# ─── Auth ─────────────────────────────────────────────────────────────────────
_get_token() {
  if [[ -f "$TOKEN_FILE" ]]; then
    cat "$TOKEN_FILE"
  else
    warn "Não autenticado. Execute: ./scripts/manage.sh login"
    exit 1
  fi
}

cmd_login() {
  local username password
  read -rp "Username: " username
  read -rsp "Password: " password; echo

  response=$(curl -sf -X POST "$BACKEND_URL/api/v1/auth/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=$username&password=$password") || error "Login falhou — verifique as credenciais"

  token=$(echo "$response" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
  echo "$token" > "$TOKEN_FILE"
  chmod 600 "$TOKEN_FILE"

  user=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin)['user']; print(f\"{d['username']} ({d['role']})\")")
  log "Autenticado como: $user"
}

cmd_logout() {
  TOKEN=$(_get_token)
  curl -sf -X POST "$BACKEND_URL/api/v1/auth/logout" -H "Authorization: Bearer $TOKEN" > /dev/null
  rm -f "$TOKEN_FILE"
  log "Logout realizado"
}

# ─── User Management ──────────────────────────────────────────────────────────
cmd_user() {
  local subcmd="${1:-list}"
  shift || true

  case "$subcmd" in
    create)
      local username="" password="" role="viewer" email="" full_name=""

      while [[ $# -gt 0 ]]; do
        case "$1" in
          --username) username="$2"; shift 2 ;;
          --password) password="$2"; shift 2 ;;
          --role)     role="$2"; shift 2 ;;
          --email)    email="$2"; shift 2 ;;
          --full-name) full_name="$2"; shift 2 ;;
          *) shift ;;
        esac
      done

      [[ -z "$username" ]] && read -rp "Username: " username
      [[ -z "$email" ]] && read -rp "Email: " email
      [[ -z "$password" ]] && { read -rsp "Senha: " password; echo; }
      [[ -z "$full_name" ]] && read -rp "Nome completo [opcional]: " full_name

      TOKEN=$(_get_token)
      payload=$(python3 -c "
import json
print(json.dumps({
  'username': '$username',
  'email': '$email',
  'password': '$password',
  'full_name': '$full_name',
  'role': '$role'
}))
")
      response=$(curl -sf -X POST "$BACKEND_URL/api/v1/users/" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "$payload") || error "Falha ao criar usuário"

      log "Usuário criado: $username (role: $role)"
      echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'  ID: {d[\"id\"]}  |  Email: {d[\"email\"]}  |  Status: {d[\"status\"]}')"
      ;;

    list)
      TOKEN=$(_get_token)
      response=$(curl -sf "$BACKEND_URL/api/v1/users/" -H "Authorization: Bearer $TOKEN")
      echo -e "\n${BOLD}Usuários cadastrados:${NC}"
      echo "$response" | python3 -c "
import sys, json
users = json.load(sys.stdin)
print(f'{'ID':38} {'Username':20} {'Email':30} {'Role':20} {'Status':12} {'Last Login':25}')
print('-' * 140)
for u in users:
    ll = u.get('last_login', 'Never') or 'Never'
    print(f\"{u['id']:38} {u['username']:20} {u['email']:30} {u['role']:20} {u['status']:12} {str(ll):25}\")
print(f'\nTotal: {len(users)} usuários')
"
      ;;

    update)
      local user_id="" role="" status_val=""
      while [[ $# -gt 0 ]]; do
        case "$1" in
          --id)     user_id="$2"; shift 2 ;;
          --role)   role="$2"; shift 2 ;;
          --status) status_val="$2"; shift 2 ;;
          *) shift ;;
        esac
      done

      [[ -z "$user_id" ]] && read -rp "User ID: " user_id
      TOKEN=$(_get_token)

      payload="{}"
      [[ -n "$role" ]] && payload=$(echo "$payload" | python3 -c "import sys,json; d=json.load(sys.stdin); d['role']='$role'; print(json.dumps(d))")
      [[ -n "$status_val" ]] && payload=$(echo "$payload" | python3 -c "import sys,json; d=json.load(sys.stdin); d['status']='$status_val'; print(json.dumps(d))")

      curl -sf -X PUT "$BACKEND_URL/api/v1/users/$user_id" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "$payload" > /dev/null || error "Falha ao atualizar usuário"

      log "Usuário $user_id atualizado"
      ;;

    delete)
      local user_id="${1:-}"
      [[ -z "$user_id" ]] && read -rp "User ID para desativar: " user_id
      TOKEN=$(_get_token)
      curl -sf -X DELETE "$BACKEND_URL/api/v1/users/$user_id" \
        -H "Authorization: Bearer $TOKEN" > /dev/null || error "Falha ao desativar usuário"
      log "Usuário $user_id desativado"
      ;;

    unlock)
      local user_id="${1:-}"
      [[ -z "$user_id" ]] && read -rp "User ID para desbloquear: " user_id
      TOKEN=$(_get_token)
      curl -sf -X PUT "$BACKEND_URL/api/v1/users/$user_id/unlock" \
        -H "Authorization: Bearer $TOKEN" > /dev/null || error "Falha ao desbloquear"
      log "Usuário $user_id desbloqueado"
      ;;

    *)
      echo "Uso: manage.sh user [create|list|update|delete|unlock]"
      ;;
  esac
}

# ─── Secrets Management ───────────────────────────────────────────────────────
cmd_secrets() {
  local subcmd="${1:-list}"; shift || true

  # Verificar se Vault está disponível
  VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
  VAULT_TOKEN_VAL="${VAULT_TOKEN:-}"

  if [[ -z "$VAULT_TOKEN_VAL" ]] && [[ -f "$SCRIPT_DIR/.env" ]]; then
    VAULT_TOKEN_VAL=$(grep "^VAULT_TOKEN=" "$SCRIPT_DIR/.env" | cut -d= -f2)
  fi

  case "$subcmd" in
    set)
      local key="${1:-}" value="${2:-}"
      [[ -z "$key" ]] && read -rp "Nome do segredo (ex: sentinelone/api_token): " key
      [[ -z "$value" ]] && { read -rsp "Valor: " value; echo; }

      curl -sf -X POST "$VAULT_ADDR/v1/secret/data/sdl/$key" \
        -H "X-Vault-Token: $VAULT_TOKEN_VAL" \
        -H "Content-Type: application/json" \
        -d "{\"data\":{\"value\":\"$value\"}}" > /dev/null || error "Falha ao salvar no Vault"

      log "Segredo '$key' salvo no Vault"
      ;;

    get)
      local key="${1:-}"
      [[ -z "$key" ]] && read -rp "Nome do segredo: " key

      curl -sf "$VAULT_ADDR/v1/secret/data/sdl/$key" \
        -H "X-Vault-Token: $VAULT_TOKEN_VAL" | \
        python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data']['data'].get('value','(não encontrado)'))"
      ;;

    list)
      echo -e "\n${BOLD}Segredos no Vault (sdl/):${NC}"
      curl -sf -X LIST "$VAULT_ADDR/v1/secret/metadata/sdl" \
        -H "X-Vault-Token: $VAULT_TOKEN_VAL" | \
        python3 -c "
import sys,json
try:
    d = json.load(sys.stdin)
    keys = d.get('data', {}).get('keys', [])
    for k in keys:
        print(f'  • {k}')
    print(f'\nTotal: {len(keys)} segredos')
except:
    print('Nenhum segredo configurado ainda')
"
      ;;

    delete)
      local key="${1:-}"
      [[ -z "$key" ]] && read -rp "Nome do segredo a remover: " key
      read -rp "Confirmar remoção de '$key'? [s/N]: " confirm
      [[ "$confirm" != "s" ]] && { info "Cancelado"; return; }

      curl -sf -X DELETE "$VAULT_ADDR/v1/secret/metadata/sdl/$key" \
        -H "X-Vault-Token: $VAULT_TOKEN_VAL" > /dev/null
      log "Segredo '$key' removido"
      ;;

    setup-all)
      info "Configuração interativa de todas as API keys"
      local sources=("sentinelone/api_token" "sentinelone/base_url"
                     "qualys/username" "qualys/password"
                     "proofpoint/service_principal" "proofpoint/secret"
                     "mantis/api_key" "ciso_assistance/api_key"
                     "ms_security/tenant_id" "ms_security/client_id" "ms_security/client_secret"
                     "aws_security/access_key_id" "aws_security/secret_access_key"
                     "google_security/project_id" "fortigate/api_key")

      for key in "${sources[@]}"; do
        read -rsp "  $key (Enter para pular): " val; echo
        if [[ -n "$val" ]]; then
          cmd_secrets set "$key" "$val"
        fi
      done
      log "Configuração de segredos concluída"
      ;;
    *)
      echo "Uso: manage.sh secrets [set|get|list|delete|setup-all]"
      ;;
  esac
}

# ─── Pipeline Management ──────────────────────────────────────────────────────
cmd_pipeline() {
  local subcmd="${1:-status}"; shift || true

  TOKEN=$(_get_token)
  case "$subcmd" in
    trigger)
      local source="${1:-all}"
      if [[ "$source" == "all" ]]; then
        curl -sf -X POST "$BACKEND_URL/api/v1/pipelines/trigger-all" \
          -H "Authorization: Bearer $TOKEN" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['message'])"
      else
        curl -sf -X POST "$BACKEND_URL/api/v1/pipelines/trigger/$source" \
          -H "Authorization: Bearer $TOKEN" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['message'])"
      fi
      ;;

    status)
      echo -e "\n${BOLD}Status dos últimos pipeline runs:${NC}"
      curl -sf "$BACKEND_URL/api/v1/pipelines/runs?limit=20" \
        -H "Authorization: Bearer $TOKEN" | \
        python3 -c "
import sys, json
runs = json.load(sys.stdin)
if not runs:
    print('Nenhum pipeline executado ainda')
else:
    print(f'{'Source':20} {'Status':12} {'Records':10} {'Duration':12} {'Started':25}')
    print('-' * 90)
    for r in runs:
        d = r.get('duration_seconds') or 0
        print(f\"{r['source']:20} {r['status']:12} {r['records_processed']:10} {str(round(d,1))+'s':12} {str(r['started_at'])[:25]:25}\")
"
      ;;

    test)
      local source="${1:-}"
      [[ -z "$source" ]] && { error "Especifique a fonte: manage.sh pipeline test <source>"; }
      echo -e "\n${BOLD}Testando conexão: $source${NC}"
      curl -sf -X POST "$BACKEND_URL/api/v1/pipelines/credentials/$source/test" \
        -H "Authorization: Bearer $TOKEN" | \
        python3 -c "import sys,json; d=json.load(sys.stdin); status='✓ OK' if d.get('success') else '✗ FALHOU'; print(f\"Resultado: {status}\")"
      ;;

    test-all)
      echo -e "\n${BOLD}Testando todas as conexões:${NC}"
      for src in sentinelone qualys proofpoint mantis ciso_assistance ms_security aws_security google_security fortigate; do
        result=$(curl -sf -X POST "$BACKEND_URL/api/v1/pipelines/credentials/$src/test" \
          -H "Authorization: Bearer $TOKEN" | \
          python3 -c "import sys,json; d=json.load(sys.stdin); print('OK' if d.get('success') else 'FAIL')")
        if [[ "$result" == "OK" ]]; then
          log "$src"
        else
          warn "$src — não configurado ou falhou"
        fi
      done
      ;;

    *)
      echo "Uso: manage.sh pipeline [trigger|status|test|test-all]"
      ;;
  esac
}

# ─── Audit Logs ───────────────────────────────────────────────────────────────
cmd_audit() {
  local limit="${1:-50}"
  TOKEN=$(_get_token)
  echo -e "\n${BOLD}Últimos $limit registros de auditoria:${NC}"
  curl -sf "$BACKEND_URL/api/v1/audit/logs?limit=$limit" \
    -H "Authorization: Bearer $TOKEN" | \
    python3 -c "
import sys, json
logs = json.load(sys.stdin)
print(f'{'Timestamp':25} {'User':20} {'Action':20} {'Resource':15} {'IP':16} {'OK':4}')
print('-' * 105)
for l in logs:
    ok = '✓' if l.get('success') else '✗'
    ts = str(l.get('created_at',''))[:25]
    print(f\"{ts:25} {str(l.get('username','system')):20} {str(l.get('action','')):20} {str(l.get('resource_type','')):15} {str(l.get('ip_address','')):16} {ok:4}\")
print(f'\nExibindo {len(logs)} registros')
"
}

# ─── Service Control ──────────────────────────────────────────────────────────
cmd_service() {
  local action="${1:-status}"
  cd "$SCRIPT_DIR"
  case "$action" in
    start)   docker compose up -d; log "Serviços iniciados" ;;
    stop)    docker compose down; log "Serviços parados" ;;
    restart) docker compose restart; log "Serviços reiniciados" ;;
    status)  docker compose ps ;;
    logs)    docker compose logs -f "${2:-}" ;;
    rebuild) docker compose build --no-cache && docker compose up -d ;;
    *)       echo "Uso: manage.sh service [start|stop|restart|status|logs|rebuild]" ;;
  esac
}

# ─── Backup ───────────────────────────────────────────────────────────────────
cmd_backup() {
  local backup_dir="$SCRIPT_DIR/backups"
  mkdir -p "$backup_dir"
  local filename="sdl_backup_$(date +%Y%m%d_%H%M%S).sql.gz"

  info "Criando backup do PostgreSQL..."
  docker compose exec -T postgres pg_dump \
    -U "$POSTGRES_USER" security_data_lake | gzip > "$backup_dir/$filename"

  log "Backup criado: $backup_dir/$filename"
  ls -lh "$backup_dir" | tail -5
}

# ─── Help ─────────────────────────────────────────────────────────────────────
cmd_help() {
  cat << EOF

${BOLD}Security Data Lake — Management CLI${NC}

${BOLD}Autenticação:${NC}
  manage.sh login                         Login na API
  manage.sh logout                        Logout

${BOLD}Usuários:${NC}
  manage.sh user create [--username x --role admin]    Criar usuário
  manage.sh user list                                  Listar usuários
  manage.sh user update --id <id> --role analyst       Atualizar usuário
  manage.sh user delete <id>                           Desativar usuário
  manage.sh user unlock <id>                           Desbloquear usuário

${BOLD}Segredos / API Keys:${NC}
  manage.sh secrets set sentinelone/api_token "KEY"   Salvar segredo no Vault
  manage.sh secrets get sentinelone/api_token          Ler segredo
  manage.sh secrets list                               Listar segredos
  manage.sh secrets delete sentinelone/api_token       Remover segredo
  manage.sh secrets setup-all                          Configuração interativa completa

${BOLD}Pipelines:${NC}
  manage.sh pipeline trigger [source|all]              Acionar pipeline manualmente
  manage.sh pipeline status                            Status dos pipeline runs
  manage.sh pipeline test <source>                     Testar conexão com API
  manage.sh pipeline test-all                          Testar todas as conexões

${BOLD}Auditoria:${NC}
  manage.sh audit [limit]                              Ver logs de auditoria

${BOLD}Serviços:${NC}
  manage.sh service start|stop|restart|status          Controlar containers
  manage.sh service logs [service]                     Ver logs dos containers
  manage.sh service rebuild                            Reconstruir imagens

${BOLD}Backup:${NC}
  manage.sh backup                                     Backup do PostgreSQL

EOF
}

# ─── Entry point ─────────────────────────────────────────────────────────────
case "${1:-help}" in
  login)    cmd_login ;;
  logout)   cmd_logout ;;
  user)     shift; cmd_user "$@" ;;
  secrets)  shift; cmd_secrets "$@" ;;
  pipeline) shift; cmd_pipeline "$@" ;;
  audit)    shift; cmd_audit "$@" ;;
  service)  shift; cmd_service "$@" ;;
  backup)   cmd_backup ;;
  help|--help|-h) cmd_help ;;
  *)
    error "Comando desconhecido: $1. Use: manage.sh help"
    ;;
esac
