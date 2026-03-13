# Arquitetura Técnica — Security Data Lake

## Decisões de Design

### Por que ELT e não ETL?
Optamos por **ELT (Extract, Load, Transform)** porque:
- Os dados brutos das APIs são preservados em `raw_data` (JSON) para auditoria
- A transformação/normalização ocorre na camada de aplicação, com schema flexível
- Facilita reprocessamento histórico sem precisar re-extrair das APIs

### Esquema de Normalização de Ativos

O problema central é: **como saber que o "DESKTOP-ABC123" no SentinelOne é o mesmo ativo que o "192.168.1.50" no Qualys?**

```
Estratégia de resolução de Asset ID:

1. Prioridade de matching (em ordem):
   a. vendor_asset_id → ID único do fabricante (mais confiável)
   b. hostname (normalizado lowercase) → chave secundária
   c. ip_address → fallback (pode mudar com DHCP!)
   d. mac_address → confiável mas nem sempre disponível

2. Algoritmo:
   for each incoming record:
     1. Tenta encontrar por vendor_id do fabricante
     2. Se não encontrou, tenta por hostname
     3. Se não encontrou, tenta por IP
     4. Se não encontrou, cria novo Asset com UUID interno
     5. Enriquece o asset com dados de todas as fontes que o conhecem
```

### Por que PostgreSQL + Elasticsearch?
- **PostgreSQL**: metadados estruturados, users, audit logs, relações. ACID compliant.
- **Elasticsearch**: eventos de segurança (ThreatEvents), queries de full-text em logs, visualização no Kibana
- **Redis**: cache de KPIs, rate limiting, sessões

### Gerenciamento de Segredos — HashiCorp Vault
```
Fluxo de credencial:
  1. Admin configura API key via: ./scripts/manage.sh secrets set sentinelone/api_token "KEY"
  2. Key é gravada no Vault: secret/sdl/sentinelone/api_token
  3. No runtime, o conector chama VaultClient.get_secret("sentinelone/api_token")
  4. Vault retorna o valor decriptado na memória
  5. Nunca persiste em .env, nunca aparece em logs

Para produção: substituir Vault Dev mode por Vault com Raft Storage + TLS
```

### Orquestração com Apache Airflow
```
DAGs disponíveis:
  security_telemetry_pipeline     → a cada hora (schedule: 0 * * * *)
  security_telemetry_full_sync    → diário 1h AM (schedule: 0 1 * * *)

Execução dos tasks:
  [start]
    ├── endpoint_vuln_sources (SentinelOne, Qualys) ──┐
    ├── cloud_sources (MS, AWS, GCP)                  ├── [health_check] → [end]
    ├── threat_sources (Proofpoint, Mantis)            |
    └── grc_network_sources (CISO, Fortigate) ─────────┘

  Retry: 3x com exponential backoff (5min, 10min, 20min)
  Timeout por task: 30 min
```

## Fluxo de Dados Completo
```
API Fonte
  └─► Conector (connector.fetch_all())
        └─► Normalização (connector.normalize_and_store())
              ├─► Asset matching/upsert → PostgreSQL
              ├─► Vulnerability upsert  → PostgreSQL
              ├─► ThreatEvent insert    → PostgreSQL + Elasticsearch
              └─► PipelineRun update    → PostgreSQL

Dashboard
  └─► /api/v1/dashboard/kpis   → SQL aggregations no PostgreSQL
  └─► /api/v1/dashboard/trends → time-series queries
  └─► Kibana                   → Elasticsearch visualizations
```

## Segurança da Aplicação
- **Autenticação**: JWT com refresh tokens (access: 60min, refresh: 7 dias)
- **Autorização**: RBAC (admin, analyst, pipeline_manager, viewer)
- **Rate limiting**: Nginx (30 req/min global, 10/min em /auth/token)
- **Audit log**: 100% das ações de usuário gravadas em audit_logs
- **Password policy**: mínimo 12 chars, 1 maiúscula, 1 número, bcrypt hash
- **Lockout**: 5 tentativas falhas → conta bloqueada (admin desbloqueia)
- **Headers de segurança**: HSTS, X-Frame-Options, CSP via Nginx
- **Secrets**: Vault (nunca em env vars em produção)

## Escalabilidade
Para escalar horizontalmente:
- Backend FastAPI: adicionar mais réplicas atrás do Nginx (upstream pool)
- Airflow: aumentar workers no docker-compose
- PostgreSQL → migrar para Aurora ou RDS com replicas de leitura
- Elasticsearch → cluster multi-node
- Para volumes > 100GB/mês: considerar BigQuery ou S3 + Athena como data lake externo
