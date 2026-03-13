from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from database import get_db
from models import User, UserStatus, AuditLog, AuditAction
from config import settings
import logging

logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido ou expirado",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciais inválidas",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_token(token)
        username: str = payload.get("sub")
        if not username:
            raise credentials_exception
    except HTTPException:
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise credentials_exception
    if user.status == UserStatus.INACTIVE:
        raise HTTPException(status_code=403, detail="Conta inativa")
    if user.status == UserStatus.LOCKED:
        raise HTTPException(status_code=403, detail="Conta bloqueada")
    return user


def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    if current_user.status != UserStatus.ACTIVE:
        raise HTTPException(status_code=403, detail="Usuário inativo")
    return current_user


def require_role(*roles):
    """Dependency factory para verificar roles."""
    def role_checker(current_user: User = Depends(get_current_active_user)):
        if current_user.role not in roles and not current_user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permissão insuficiente. Requerido: {[r.value for r in roles]}"
            )
        return current_user
    return role_checker


def authenticate_user(db: Session, username: str, password: str, ip: str = None) -> Optional[User]:
    user = db.query(User).filter(User.username == username).first()

    if not user:
        _log_audit(db, None, username, AuditAction.LOGIN_FAILED, ip, "Usuário não encontrado", False)
        return None

    if user.status == UserStatus.LOCKED:
        _log_audit(db, user.id, username, AuditAction.LOGIN_FAILED, ip, "Conta bloqueada", False)
        raise HTTPException(status_code=403, detail="Conta bloqueada por tentativas excessivas")

    if not verify_password(password, user.hashed_password):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= 5:
            user.status = UserStatus.LOCKED
            logger.warning(f"User {username} locked after {user.failed_login_attempts} failed attempts")
        db.commit()
        _log_audit(db, user.id, username, AuditAction.LOGIN_FAILED, ip, "Senha incorreta", False)
        return None

    # Reset on success
    user.failed_login_attempts = 0
    user.last_login = datetime.now(timezone.utc)
    user.last_login_ip = ip
    db.commit()
    _log_audit(db, user.id, username, AuditAction.LOGIN, ip, "Login bem-sucedido", True)
    return user


def _log_audit(db: Session, user_id, username, action, ip, description, success):
    try:
        log = AuditLog(
            user_id=user_id,
            username=username,
            action=action,
            ip_address=ip,
            description=description,
            success=success,
            resource_type="auth"
        )
        db.add(log)
        db.commit()
    except Exception as e:
        logger.error(f"Failed to write audit log: {e}")
        db.rollback()


def log_audit(
    db: Session,
    user: User,
    action: AuditAction,
    resource_type: str = None,
    resource_id: str = None,
    description: str = None,
    old_values: dict = None,
    new_values: dict = None,
    ip: str = None,
    success: bool = True
):
    try:
        entry = AuditLog(
            user_id=user.id if user else None,
            username=user.username if user else None,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            description=description,
            old_values=old_values,
            new_values=new_values,
            ip_address=ip,
            success=success,
        )
        db.add(entry)
        db.commit()
    except Exception as e:
        logger.error(f"Audit log error: {e}")
        db.rollback()
