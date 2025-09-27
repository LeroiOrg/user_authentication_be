import os
import jwt
from datetime import timedelta, datetime, timezone
from fastapi import HTTPException
from fastapi_mail import MessageSchema
from sqlalchemy.orm import Session

from app.models.user_model import User
from app.models.blocked_email import BlockedEmail
from app.services.auth_service import (
    get_password_hash,
    create_access_token,
    decode_access_token,
    verify_password,
    save_verification_code,
    verify_code,
)
from app.services.email_service import fastmail
from app.services.auth_service import login_or_register_google

# Read from environment (.env loaded by runtime) with safe defaults
SECRET_KEY = os.getenv("SECRET_KEY", "secret")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
# No hardcoded fallback; must come from environment
FRONTEND_URL = os.getenv("FRONTEND_URL")


def check_email_exists(db: Session, email: str) -> dict:
    user = db.query(User).filter_by(email=email).first()
    return {"status": "success", "exists": user is not None}


async def send_verification_email(db: Session, email: str, code: str) -> dict:
    try:
        save_verification_code(db, email, code)
        message = MessageSchema(
            subject="Verificación de email - LEROI",
            recipients=[email],
            body=(
                f"<html>"
                f"<body style='font-family: Arial, sans-serif; text-align: center; margin: 0; padding: 40px;'>"
                f"<h1 style='font-size: 30px; font-weight: bold; color: #ffb923;'>Código de Verificación</h1>"
                f"<p style='font-size: 20px; color: #000000;'>Tu código de verificación es:</p>"
                f"<h2 style='font-size: 40px; color: #835bfc;'>{code}</h2>"
                f"<p style='font-size: 16px; color: #000000;'>Este código expirará en 5 minutos.</p>"
                f"<p style='font-size: 16px; color: #000000;'>Si no solicitaste este código, puedes ignorar este email.</p>"
                f"</body>"
                f"</html>"
            ),
            subtype="html",
        )
        await fastmail.send_message(message)
        return {"status": "success", "message": "Código de verificación enviado", "email": email}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al enviar el email: {str(e)}")


def _ensure_not_temporarily_blocked(blocked_user: BlockedEmail | None):
    if blocked_user and blocked_user.blocked_until and blocked_user.blocked_until.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="Tu cuenta está bloqueada temporalmente. Intenta más tarde.")


def _register_failed_attempt_and_maybe_block(db: Session, blocked_user: BlockedEmail | None, email: str):
    if not blocked_user:
        blocked_user = BlockedEmail(email=email, failed_attempts=1)
        db.add(blocked_user)
    else:
        blocked_user.failed_attempts += 1
    MAX_ATTEMPTS = 5
    BLOCK_TIME = timedelta(minutes=15)
    if blocked_user.failed_attempts >= MAX_ATTEMPTS:
        blocked_user.blocked_until = datetime.now(timezone.utc) + BLOCK_TIME
        db.commit()
        raise HTTPException(
            status_code=403,
            detail="Tu cuenta ha sido bloqueada temporalmente debido a intentos fallidos.",
        )
    db.commit()
    return blocked_user


def _clear_block_if_exists(db: Session, blocked_user: BlockedEmail | None):
    if blocked_user:
        db.delete(blocked_user)
        db.commit()


def verify_code_for_registration(db: Session, email: str, code: str) -> dict:
    blocked_user = db.query(BlockedEmail).filter_by(email=email).first()
    _ensure_not_temporarily_blocked(blocked_user)
    if verify_code(db, email, code):
        _clear_block_if_exists(db, blocked_user)
        return {"status": "success", "message": "Código de verificación correcto"}
    _register_failed_attempt_and_maybe_block(db, blocked_user, email)
    raise HTTPException(status_code=400, detail="Código de verificación incorrecto o expirado")


def verify_2fa_code(db: Session, email: str, code: str) -> dict:
    blocked_user = db.query(BlockedEmail).filter_by(email=email).first()
    _ensure_not_temporarily_blocked(blocked_user)
    if verify_code(db, email, code):
        _clear_block_if_exists(db, blocked_user)
        user = db.query(User).filter_by(email=email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        access_token = create_access_token(
            data={
                "sub": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "email": user.email,
                "provider": user.provider,
                "user_id": user.user_id,
            }
        )
        return {
            "status": "success",
            "message": "Código de verificación correcto",
            "access_token": access_token,
            "token_type": "bearer",
        }
    _register_failed_attempt_and_maybe_block(db, blocked_user, email)
    raise HTTPException(status_code=400, detail="Código de verificación incorrecto o expirado")


def register_user(db: Session, first_name: str, last_name: str | None, email: str, password: str | None, provider: str) -> dict:
    blocked_email = db.query(BlockedEmail).filter(BlockedEmail.email == email).first()
    if blocked_email:
        raise HTTPException(status_code=400, detail="Este email está bloqueado y no puede registrarse.")
    hashed_password = get_password_hash(password) if password else None
    user = User(
        first_name=first_name,
        last_name=last_name if last_name else '',
        email=email,
        password=hashed_password,
        provider=provider,
        credits=1000,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"status": "success", "message": "Usuario registrado correctamente"}


def login_user(db: Session, email: str, password: str) -> dict:
    user = db.query(User).filter_by(email=email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    if user.provider == "google":
        raise HTTPException(status_code=401, detail="Ya has iniciado sesión con Google")
    blocked_user = db.query(BlockedEmail).filter_by(email=email).first()
    _ensure_not_temporarily_blocked(blocked_user)
    if not verify_password(password, user.password):
        _register_failed_attempt_and_maybe_block(db, blocked_user, email)
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")
    if user.tfa_enabled:
        return {"status": "2fa_required", "message": "Se requiere autenticación de doble factor", "email": user.email}
    _clear_block_if_exists(db, blocked_user)
    access_token = create_access_token(
        data={
            "user_id": user.user_id,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
            "provider": user.provider,
            "tfa_enabled": user.tfa_enabled,
        }
    )
    return {
        "msg": "Login exitoso",
        "user_id": user.user_id,
        "access_token": access_token,
        "token_type": "bearer",
    }


def validate_token(token: str) -> dict:
    try:
        payload = decode_access_token(token)
        return {"status": "success", "message": "Token válido", "data": payload}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")


async def forgot_password(db: Session, email: str) -> dict:
    user = db.query(User).filter_by(email=email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    try:
        if not FRONTEND_URL:
            # Fail fast if FRONTEND_URL is not configured
            raise HTTPException(status_code=500, detail="FRONTEND_URL no configurada en el entorno")
        reset_token = create_access_token(
            data={
                "user_id": user.user_id,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "email": user.email,
                "provider": user.provider,
                "tfa_enabled": user.tfa_enabled,
            },
            expires_delta=timedelta(minutes=10),
        )
        reset_link = f"{FRONTEND_URL}/reset-password?token={reset_token}"
        message = MessageSchema(
            subject="Restablecimiento de Contraseña - LEROI",
            recipients=[email],
            body=(
                f"<html>"
                f"<body style='font-family: Arial, sans-serif; text-align: center; margin: 0; padding: 40px;'>"
                f"<h1 style='font-size: 30px; font-weight: bold; color: #ffb923;'>Restablecimiento de Contraseña</h1>"
                f"<p style='font-size: 20px; color: #000000;'>Haz clic en el enlace para restablecer tu contraseña:</p>"
                f"<a href='{reset_link}' style='font-size: 20px; color: #835bfc;'>Restablecer Contraseña</a>"
                f"<p style='font-size: 16px; color: #000000;'>Este enlace expirará en 10 minutos.</p>"
                f"<p style='font-size: 16px; color: #000000;'>Si no solicitaste este cambio, puedes ignorar este email.</p>"
                f"</body>"
                f"</html>"
            ),
            subtype="html",
        )
        await fastmail.send_message(message)
        return {"status": "success", "message": "Enlace de restablecimiento enviado", "email": email}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al enviar el email: {str(e)}")


def reset_password(db: Session, token: str, new_password: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("email")
        if email is None:
            raise HTTPException(status_code=400, detail="Token inválido")
        user = db.query(User).filter_by(email=email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        user.password = get_password_hash(new_password)
        db.commit()
        return {"status": "success", "message": "Contraseña cambiada correctamente"}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="El token ha expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=400, detail="Token inválido")


def get_blocked_email(db: Session, email: str):
    blocked = db.query(BlockedEmail).filter_by(email=email).first()
    if not blocked:
        raise HTTPException(status_code=404, detail="email no bloqueado")
    return blocked


def get_user_profile(token: str, db: Session) -> dict:
    try:
        payload = decode_access_token(token)
        email = payload.get("email")
        if not email:
            raise HTTPException(status_code=400, detail="Token inválido")
        user = db.query(User).filter_by(email=email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        return {
            "status": "success",
            "data": {
                "firstName": user.first_name,
                "lastName": user.last_name,
                "email": user.email,
                "credits": user.credits,
                "provider": user.provider,
                "tfa_enabled": user.tfa_enabled,
            },
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")


def update_2fa_status(token: str, db: Session, is_2fa_enabled: bool) -> dict:
    try:
        payload = decode_access_token(token)
        email = payload.get("email")
        if not email:
            raise HTTPException(status_code=400, detail="Token inválido")
        user = db.query(User).filter_by(email=email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        user.tfa_enabled = is_2fa_enabled
        db.commit()
        return {
            "status": "success",
            "message": "Estado de 2FA actualizado correctamente",
            "data": {"tfa_enabled": user.tfa_enabled},
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error al actualizar el estado de 2FA: {str(e)}")


def delete_user(token: str, db: Session, email: str) -> dict:
    try:
        payload = decode_access_token(token)
        authenticated_email = payload.get("email")
        user_role = payload.get("role") if "role" in payload else None
        if not authenticated_email:
            raise HTTPException(status_code=400, detail="Invalid token")
        if user_role != "admin" and authenticated_email != email:
            raise HTTPException(status_code=403, detail="Unauthorized action")
        user_to_delete = db.query(User).filter_by(email=email).first()
        if not user_to_delete:
            raise HTTPException(status_code=404, detail="User not found")
        # Si tienes Roadmap, descomenta y borra asociados
        # db.query(Roadmap).filter(Roadmap.user_id_creador == user_to_delete.user_id).delete(synchronize_session=False)
        db.delete(user_to_delete)
        db.commit()
        return {"status": "success", "message": "User deleted successfully", "deleted_user_email": email}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


def update_user(token: str, db: Session, request) -> dict:
    try:
        payload = decode_access_token(token)
        authenticated_email = payload.get("email")
        if not authenticated_email:
            raise HTTPException(status_code=400, detail="Token inválido")
        user = db.query(User).filter(User.email == authenticated_email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        # Mantener exactamente la lógica original (aunque tenga redundancias)
        if request.first_name or request.first_name:
            user.first_name = request.first_name if request.first_name is not None else request.first_name
        if request.last_name or request.last_name:
            user.last_name = request.last_name if request.last_name is not None else request.last_name
        if request.email or request.email:
            user.email = request.email if request.email is not None else request.email
        if request.provider or request.provider:
            user.provider = request.provider if request.provider is not None else request.provider
        db.commit()
        return {
            "status": "success",
            "message": "Datos de usuario actualizados correctamente",
            "data": {
                "first_name": user.first_name,
                "last_name": user.last_name,
                "email": user.email,
                "provider": user.provider,
            },
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


def get_user_credits(token: str, db: Session, email: str) -> dict:
    try:
        decode_access_token(token)
        user = db.query(User).filter_by(email=email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        return {"status": "success", "email": email, "credits": user.credits}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")


def update_user_credits(token: str, db: Session, email: str, amount: int) -> dict:
    try:
        decode_access_token(token)
        user = db.query(User).filter_by(email=email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        user.credits += amount
        if user.credits < 0:
            user.credits = 0
        db.commit()
        return {"status": "success", "email": email, "credits": user.credits}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")


def login_with_google(db: Session, email: str, first_name: str) -> dict:
    """Inicia sesión o registra un usuario con Google y devuelve el access_token.
    Conserva exactamente el comportamiento original del endpoint.
    """
    user = login_or_register_google(db, email, first_name)
    access_token = create_access_token(
        data={
            "user_id": user.user_id,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
            "provider": user.provider,
            "tfa_enabled": user.tfa_enabled,
        }
    )
    return {"status": "success", "access_token": access_token, "token_type": "bearer"}
