from sqlalchemy import (
    Column, String, Integer, Boolean, DateTime, Text,
    JSON, ForeignKey, Enum, Float, Index
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base
import enum
import uuid


def gen_uuid():
    return str(uuid.uuid4())


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    PIPELINE_MANAGER = "pipeline_manager"


class UserStatus(str, enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    LOCKED = "locked"


class AuditAction(str, enum.Enum):
    LOGIN = "login"
    LOGOUT = "logout"
    LOGIN_FAILED = "login_failed"
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    READ = "read"
    PIPELINE_RUN = "pipeline_run"
    SECRET_ACCESS = "secret_access"
    CONFIG_CHANGE = "config_change"
    PASSWORD_CHANGE = "password_change"


class PipelineStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"


# ─── Usuários ──────────────────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    role = Column(Enum(UserRole), default=UserRole.VIEWER, nullable=False)
    status = Column(Enum(UserStatus), default=UserStatus.ACTIVE, nullable=False)
    is_superuser = Column(Boolean, default=False)
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(64), nullable=True)
    failed_login_attempts = Column(Integer, default=0)
    last_login = Column(DateTime(timezone=True), nullable=True)
    last_login_ip = Column(String(45), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    created_by = Column(String(36), ForeignKey("users.id"), nullable=True)

    profile = relationship("UserProfile", back_populates="user", uselist=False, cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user", foreign_keys="AuditLog.user_id")


class UserProfile(Base):
    __tablename__ = "user_profiles"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), unique=True, nullable=False)
    department = Column(String(128), nullable=True)
    phone = Column(String(32), nullable=True)
    timezone = Column(String(64), default="America/Sao_Paulo")
    language = Column(String(16), default="pt-BR")
    notification_email = Column(Boolean, default=True)
    notification_slack = Column(Boolean, default=False)
    slack_webhook = Column(String(512), nullable=True)
    dashboard_layout = Column(JSON, nullable=True)
    allowed_sources = Column(JSON, default=list)  # lista de fontes permitidas
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    user = relationship("User", back_populates="profile")


# ─── Audit Log ────────────────────────────────────────────────────────────────
class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    username = Column(String(64), nullable=True)  # denormalized for display
    action = Column(Enum(AuditAction), nullable=False)
    resource_type = Column(String(64), nullable=True)
    resource_id = Column(String(255), nullable=True)
    description = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(512), nullable=True)
    old_values = Column(JSON, nullable=True)
    new_values = Column(JSON, nullable=True)
    success = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="audit_logs", foreign_keys=[user_id])

    __table_args__ = (
        Index("ix_audit_logs_created_at", "created_at"),
        Index("ix_audit_logs_user_id", "user_id"),
        Index("ix_audit_logs_action", "action"),
    )


# ─── Assets (Inventário Unificado) ────────────────────────────────────────────
class Asset(Base):
    __tablename__ = "assets"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    hostname = Column(String(255), nullable=True, index=True)
    fqdn = Column(String(512), nullable=True)
    ip_address = Column(String(45), nullable=True, index=True)
    mac_address = Column(String(17), nullable=True)
    cloud_instance_id = Column(String(255), nullable=True)
    cloud_provider = Column(String(32), nullable=True)  # aws, azure, gcp
    cloud_region = Column(String(64), nullable=True)

    # IDs nas ferramentas de origem
    sentinelone_id = Column(String(255), nullable=True, index=True)
    qualys_id = Column(String(255), nullable=True, index=True)
    ms_device_id = Column(String(255), nullable=True)
    aws_instance_id = Column(String(255), nullable=True)

    os_name = Column(String(128), nullable=True)
    os_version = Column(String(128), nullable=True)
    os_platform = Column(String(64), nullable=True)
    asset_type = Column(String(64), nullable=True)  # server, workstation, container, vm
    environment = Column(String(64), nullable=True)  # prod, dev, staging
    tags = Column(JSON, default=dict)
    owner = Column(String(255), nullable=True)
    department = Column(String(128), nullable=True)

    is_active = Column(Boolean, default=True)
    risk_score = Column(Float, default=0.0)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    vulnerabilities = relationship("Vulnerability", back_populates="asset")
    threat_events = relationship("ThreatEvent", back_populates="asset")

    __table_args__ = (
        Index("ix_assets_hostname", "hostname"),
        Index("ix_assets_ip_address", "ip_address"),
    )


# ─── Vulnerabilidades ─────────────────────────────────────────────────────────
class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    asset_id = Column(String(36), ForeignKey("assets.id"), nullable=True)
    source = Column(String(64), nullable=False)  # qualys, sentinelone, ms
    source_vuln_id = Column(String(255), nullable=True)
    cve_id = Column(String(32), nullable=True, index=True)
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(32), nullable=False)  # critical, high, medium, low, info
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(128), nullable=True)
    cwe_id = Column(String(32), nullable=True)
    affected_software = Column(String(512), nullable=True)
    affected_version = Column(String(128), nullable=True)
    fixed_version = Column(String(128), nullable=True)
    patch_available = Column(Boolean, default=False)
    exploit_available = Column(Boolean, default=False)
    status = Column(String(32), default="open")  # open, mitigated, accepted, fixed
    first_detected = Column(DateTime(timezone=True), nullable=True)
    last_detected = Column(DateTime(timezone=True), nullable=True)
    remediated_at = Column(DateTime(timezone=True), nullable=True)
    raw_data = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    asset = relationship("Asset", back_populates="vulnerabilities")

    __table_args__ = (
        Index("ix_vuln_severity", "severity"),
        Index("ix_vuln_cve", "cve_id"),
    )


# ─── Threat Events ────────────────────────────────────────────────────────────
class ThreatEvent(Base):
    __tablename__ = "threat_events"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    asset_id = Column(String(36), ForeignKey("assets.id"), nullable=True)
    source = Column(String(64), nullable=False)
    source_event_id = Column(String(255), nullable=True)
    event_type = Column(String(128), nullable=False)
    severity = Column(String(32), nullable=False)
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)
    mitre_tactic = Column(String(128), nullable=True)
    mitre_technique = Column(String(128), nullable=True)
    ioc_type = Column(String(64), nullable=True)
    ioc_value = Column(String(512), nullable=True)
    status = Column(String(32), default="open")
    assigned_to = Column(String(64), nullable=True)
    event_timestamp = Column(DateTime(timezone=True), nullable=True, index=True)
    raw_data = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    asset = relationship("Asset", back_populates="threat_events")


# ─── Pipeline Runs ────────────────────────────────────────────────────────────
class PipelineRun(Base):
    __tablename__ = "pipeline_runs"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    pipeline_name = Column(String(128), nullable=False, index=True)
    source = Column(String(64), nullable=False)
    status = Column(Enum(PipelineStatus), default=PipelineStatus.PENDING)
    records_fetched = Column(Integer, default=0)
    records_processed = Column(Integer, default=0)
    records_failed = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    duration_seconds = Column(Float, nullable=True)
    triggered_by = Column(String(64), nullable=True)
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    finished_at = Column(DateTime(timezone=True), nullable=True)


# ─── API Credentials (metadados, sem senhas) ──────────────────────────────────
class APICredential(Base):
    __tablename__ = "api_credentials"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    source_name = Column(String(64), unique=True, nullable=False)
    display_name = Column(String(128), nullable=False)
    vault_path = Column(String(255), nullable=False)
    is_configured = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    last_tested = Column(DateTime(timezone=True), nullable=True)
    last_test_success = Column(Boolean, nullable=True)
    last_sync = Column(DateTime(timezone=True), nullable=True)
    sync_interval_minutes = Column(Integer, default=60)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


# ─── Compliance Records (GRC) ─────────────────────────────────────────────────
class ComplianceRecord(Base):
    __tablename__ = "compliance_records"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    source = Column(String(64), nullable=False)
    framework = Column(String(64), nullable=True)  # SOC2, ISO27001, LGPD, etc.
    control_id = Column(String(64), nullable=True)
    control_name = Column(String(512), nullable=True)
    status = Column(String(64), nullable=True)
    score = Column(Float, nullable=True)
    evidence = Column(Text, nullable=True)
    owner = Column(String(128), nullable=True)
    due_date = Column(DateTime(timezone=True), nullable=True)
    raw_data = Column(JSON, nullable=True)
    period_start = Column(DateTime(timezone=True), nullable=True)
    period_end = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
