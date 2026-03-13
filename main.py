from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import logging
import time
import structlog
from config import settings
from database import init_db, SessionLocal
from routers.auth_router import router as auth_router
from routers.users import router as users_router
from routers.audit import router as audit_router
from routers.dashboard import router as dashboard_router
from routers.pipelines import router as pipelines_router
from routers.data_routers import assets_router, vulns_router, threats_router

# ─── Logging ─────────────────────────────────────────────────────────────────
structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer() if settings.APP_DEBUG else structlog.processors.JSONRenderer(),
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
)
logger = structlog.get_logger()


# ─── Startup / Shutdown ───────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Security Data Lake API starting up", version=settings.APP_VERSION, env=settings.APP_ENV)
    init_db()
    _seed_initial_data()
    yield
    logger.info("Security Data Lake API shutting down")


def _seed_initial_data():
    """Seed: registra as credenciais das fontes no banco."""
    from models import APICredential
    SOURCES = [
        ("sentinelone", "SentinelOne EDR", "secret/data/sdl/sentinelone"),
        ("qualys", "Qualys VM & Patch", "secret/data/sdl/qualys"),
        ("proofpoint", "Proofpoint DLP/CASB", "secret/data/sdl/proofpoint"),
        ("mantis", "Mantis Threat Intel", "secret/data/sdl/mantis"),
        ("ciso_assistance", "CISO Assistance GRC", "secret/data/sdl/ciso_assistance"),
        ("ms_security", "Microsoft Security", "secret/data/sdl/ms_security"),
        ("aws_security", "AWS Security Hub", "secret/data/sdl/aws_security"),
        ("google_security", "Google Security SCC", "secret/data/sdl/google_security"),
        ("fortigate", "Fortigate Security Rating", "secret/data/sdl/fortigate"),
    ]
    db = SessionLocal()
    try:
        for src_name, display, vault_path in SOURCES:
            exists = db.query(APICredential).filter(APICredential.source_name == src_name).first()
            if not exists:
                db.add(APICredential(
                    source_name=src_name,
                    display_name=display,
                    vault_path=vault_path,
                    is_configured=False,
                    is_active=True,
                ))
        db.commit()
        logger.info("API credentials seeded")
    except Exception as e:
        logger.error("Seed error", error=str(e))
        db.rollback()
    finally:
        db.close()


# ─── App ─────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Security Data Lake API",
    description="Pipeline de telemetria de segurança multi-cloud/multi-vendor",
    version=settings.APP_VERSION,
    docs_url="/docs" if settings.APP_DEBUG else None,
    redoc_url="/redoc" if settings.APP_DEBUG else None,
    lifespan=lifespan,
)

# ─── Middleware ───────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost", "http://localhost:80", settings.FRONTEND_URL if hasattr(settings, 'FRONTEND_URL') else "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_logger(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    duration = round(time.time() - start, 4)
    logger.info(
        "request",
        method=request.method,
        path=request.url.path,
        status=response.status_code,
        duration_s=duration,
        ip=request.client.host if request.client else None,
    )
    return response


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# ─── Routes ──────────────────────────────────────────────────────────────────
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(audit_router)
app.include_router(dashboard_router)
app.include_router(pipelines_router)
app.include_router(assets_router)
app.include_router(vulns_router)
app.include_router(threats_router)


@app.get("/health")
def health():
    return {"status": "ok", "version": settings.APP_VERSION, "env": settings.APP_ENV}


@app.get("/")
def root():
    return {"message": "Security Data Lake API", "docs": "/docs", "health": "/health"}


# ─── Exception Handlers ───────────────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception", path=request.url.path, error=str(exc), exc_info=True)
    return JSONResponse(status_code=500, content={"detail": "Erro interno do servidor"})
