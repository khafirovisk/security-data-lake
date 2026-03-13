# 🛡️ Security Data Lake — Centralized Security Telemetry Pipeline

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11+-green.svg)
![Docker](https://img.shields.io/badge/docker-compose-blue.svg)

Pipeline de dados para centralização de telemetria de segurança multi-cloud e multi-vendor. Consolida KPIs/KRIs de múltiplas ferramentas em um repositório único para análise histórica e tendências.

## 📐 Arquitetura

```
┌─────────────────────────────────────────────────────────────────┐
│                        SOURCES (APIs)                           │
│  SentinelOne │ Qualys │ Proofpoint │ Mantis │ MS/GCP/AWS │ Forti│
└──────────────────────────┬──────────────────────────────────────┘
                           │ REST APIs
                    ┌──────▼──────┐
                    │   Airflow   │  (Orchestração / Scheduling)
                    │    DAGs     │
                    └──────┬──────┘
                           │ Normalização ELT
          ┌────────────────▼────────────────┐
          │        FastAPI Backend          │
          │  Auth │ Users │ Audit │ Pipeline│
          └────────────────┬────────────────┘
               ┌───────────┼───────────┐
          ┌────▼────┐  ┌───▼───┐  ┌───▼───┐
          │Postgres │  │Elastic│  │ Redis │
          │(Metadata│  │Search │  │(Cache)│
          │ /GRC)   │  │(Events│  │       │
          └─────────┘  └───────┘  └───────┘
                           │
                    ┌──────▼──────┐
                    │  Dashboard  │  (Web UI)
                    │  (Nginx)    │
                    └─────────────┘
```

## 🔧 Ferramentas de Origem

| # | Ferramenta | Categoria | Tipo API |
|---|-----------|-----------|----------|
| 1 | SentinelOne | EDR / Endpoint | Pública |
| 2 | Qualys | VM & Patch Management | Pública |
| 3 | Proofpoint | DLP / CASB | Pública |
| 4 | Mantis | Threat Intelligence | Pública |
| 5 | CISO Assistance | GRC | Interna |
| 6 | MS / Google / AWS Security | Cloud & Identity | Pública |
| 7 | Fortigate | Network Security Rating | Interna |

## 🚀 Quick Start (Ubuntu Server)

```bash
git clone https://github.com/khafirovisk/security-data-lake.git
cd security-data-lake
chmod +x setup.sh
sudo ./setup.sh
```

O script `setup.sh` instala todas as dependências e sobe o ambiente completo.

## 🔐 Gerenciamento de Segredos

Todas as API keys são armazenadas via **HashiCorp Vault** (container dedicado). Nunca em `.env` em produção.

```bash
# Configurar segredos
./scripts/manage.sh secrets set sentinelone_api_key "YOUR_KEY"
./scripts/manage.sh secrets set qualys_api_key "YOUR_KEY"
```

## 👥 Gerenciamento de Usuários

```bash
# Criar usuário admin
./scripts/manage.sh user create --username admin --role admin

# Listar usuários
./scripts/manage.sh user list

# Alterar perfil
./scripts/manage.sh user update --username john --role analyst
```

## 🗂️ Esquema de Normalização (Asset ID Unificado)

```
asset_id (UUID gerado internamente)
  ├── hostname        → chave de join principal
  ├── ip_address      → chave secundária
  ├── mac_address     → chave terciária
  ├── cloud_instance_id
  └── vendor_asset_id → ID original da ferramenta
```

## 📊 Endpoints da API

| Endpoint | Descrição |
|----------|-----------|
| `GET /dashboard` | KPIs consolidados |
| `GET /assets` | Inventário unificado de ativos |
| `GET /vulnerabilities` | CVEs por ativo |
| `GET /threats` | Alertas e incidentes |
| `GET /compliance` | Status GRC |
| `GET /pipelines` | Status dos pipelines |
| `GET /audit/logs` | Log de auditoria |
| `POST /users` | Criar usuário |

## 🐳 Serviços Docker

| Serviço | Porta | Descrição |
|---------|-------|-----------|
| nginx | 80/443 | Reverse Proxy / Frontend |
| backend | 8000 | FastAPI |
| airflow-webserver | 8080 | Airflow UI |
| postgres | 5432 | PostgreSQL |
| elasticsearch | 9200 | Elasticsearch |
| kibana | 5601 | Kibana |
| redis | 6379 | Cache |
| vault | 8200 | HashiCorp Vault |

## 📁 Estrutura do Projeto

```
security-data-lake/
├── backend/              # FastAPI application
│   ├── connectors/       # API connectors por ferramenta
│   ├── routers/          # Rotas da API
│   ├── schemas/          # Schemas Pydantic
│   └── middleware/       # Auth, logging middleware
├── dags/                 # Airflow DAGs
├── frontend/             # Web UI (HTML/JS/CSS)
├── nginx/                # Nginx config
├── scripts/              # CLI management tools
├── vault/                # Vault configuration
├── docker-compose.yml
├── setup.sh              # Ubuntu installer
└── .env.example
```

## 📋 Logs e Auditoria

Todas as alterações são registradas na tabela `audit_logs`:
- Login/Logout de usuários
- Alterações de configuração
- Execuções de pipeline
- CRUD de usuários

## 📜 Licença

MIT License — veja [LICENSE](LICENSE)
