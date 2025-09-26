import os
import jwt
from fastapi import APIRouter, Depends, HTTPException, status, Request, Body
from fastapi_mail import MessageSchema
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.models.user_model import User
from app.models.blocked_email import BlockedEmail
from app.models.verification_code import VerificationCode
from app.schemas.user_scheme import UserCreate, UserLogin, UserRead, BlockedEmailRead, UserUpdateRequest, UserLoginRequest, GoogleLoginRequest, EmailVerificationRequest, UserRegistrationRequest, CheckEmailRequest, SendVerificationRequest, ForgotPasswordRequest, ResetPasswordRequest
from app.services.auth_service import (
    register_user, authenticate_user, is_email_blocked, save_verification_code, verify_code,
    get_password_hash, create_access_token, decode_access_token, verify_password, login_or_register_google
)
from app.services.email_service import fastmail
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import timedelta, datetime, timezone
from pydantic import BaseModel, EmailStr
from app.schemas.credits_scheme import CreditsUpdateRequest

router = APIRouter()
security = HTTPBearer()

SECRET_KEY = os.getenv("SECRET_KEY", "secret")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Check if email exists
@router.post("/check-email")
async def check_email(request: CheckEmailRequest, db: Session = Depends(get_db)):
    email = request.email
    user = db.query(User).filter_by(email=email).first()
    return {"status": "success", "exists": user is not None}

# Send verification code
@router.post("/send-verification")
async def send_verification_email(request: SendVerificationRequest, db: Session = Depends(get_db)):
    email = request.email
    code = request.code
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
            subtype="html"
        )
        await fastmail.send_message(message)
        return {"status": "success", "message": "Código de verificación enviado", "email": email}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al enviar el email: {str(e)}")


# Verificación de código para registro (solo valida el código, no busca usuario)
@router.post("/verify-code")
async def verify_code_endpoint(request: EmailVerificationRequest, db: Session = Depends(get_db)):
    blocked_user = db.query(BlockedEmail).filter_by(email=request.email).first()
    if blocked_user:
        if blocked_user.blocked_until and blocked_user.blocked_until.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):
            raise HTTPException(
                status_code=403, detail="Tu cuenta está bloqueada temporalmente. Intenta más tarde."
            )
    if verify_code(db, request.email, request.code):
        if blocked_user:
            db.delete(blocked_user)
            db.commit()
        return {
            "status": "success",
            "message": "Código de verificación correcto"
        }
    else:
        if not blocked_user:
            blocked_user = BlockedEmail(
                email=request.email, failed_attempts=1
            )
            db.add(blocked_user)
        else:
            blocked_user.failed_attempts += 1
        MAX_ATTEMPTS = 5
        BLOCK_TIME = timedelta(minutes=15)
        if blocked_user.failed_attempts >= MAX_ATTEMPTS:
            blocked_user.blocked_until = datetime.now(timezone.utc) + BLOCK_TIME
            db.commit()
            raise HTTPException(
                status_code=403, detail="Tu cuenta ha sido bloqueada temporalmente debido a intentos fallidos."
            )
        db.commit()
        raise HTTPException(
            status_code=400,
            detail="Código de verificación incorrecto o expirado"
        )

# Verificación de código para 2FA (requiere usuario y devuelve token)
@router.post("/verify-2fa-code")
async def verify_2fa_code(request: EmailVerificationRequest, db: Session = Depends(get_db)):
    blocked_user = db.query(BlockedEmail).filter_by(email=request.email).first()
    if blocked_user:
        if blocked_user.blocked_until and blocked_user.blocked_until.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):
            raise HTTPException(
                status_code=403, detail="Tu cuenta está bloqueada temporalmente. Intenta más tarde."
            )
    if verify_code(db, request.email, request.code):
        if blocked_user:
            db.delete(blocked_user)
            db.commit()
        user = db.query(User).filter_by(email=request.email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        access_token = create_access_token(data={
            "sub": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
            "provider": user.provider,
            "user_id": user.user_id
        })
        return {
            "status": "success",
            "message": "Código de verificación correcto",
            "access_token": access_token,
            "token_type": "bearer"
        }
    else:
        if not blocked_user:
            blocked_user = BlockedEmail(
                email=request.email, failed_attempts=1
            )
            db.add(blocked_user)
        else:
            blocked_user.failed_attempts += 1
        MAX_ATTEMPTS = 5
        BLOCK_TIME = timedelta(minutes=15)
        if blocked_user.failed_attempts >= MAX_ATTEMPTS:
            blocked_user.blocked_until = datetime.now(timezone.utc) + BLOCK_TIME
            db.commit()
            raise HTTPException(
                status_code=403, detail="Tu cuenta ha sido bloqueada temporalmente debido a intentos fallidos."
            )
        db.commit()
        raise HTTPException(
            status_code=400,
            detail="Código de verificación incorrecto o expirado"
        )

# Register user
@router.post("/register")
async def register_user(request: UserRegistrationRequest, db: Session = Depends(get_db)):
    # Impedir el registro por bloqueo
    blocked_email = db.query(BlockedEmail).filter(
        BlockedEmail.email == request.email).first()
    if blocked_email:
        raise HTTPException(
            status_code=400, detail="Este email está bloqueado y no puede registrarse.")
    # Hashea la contraseña si está presente
    hashed_password = get_password_hash(request.password) if request.password else None
    # Crea un nuevo objeto de usuario
    user = User(
        first_name=request.first_name,
        last_name=request.last_name if request.last_name else '',
        email=request.email,
        password=hashed_password,
        provider=request.provider,
        credits=1000
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"status": "success", "message": "Usuario registrado correctamente"}

# Login
@router.post("/login")
async def login_user(request: UserLoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(email=request.email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    if user.provider == "google":
        raise HTTPException(status_code=401, detail="Ya has iniciado sesión con Google")
    # Bloqueo por intentos fallidos
    blocked_user = db.query(BlockedEmail).filter_by(email=request.email).first()
    if blocked_user:
        if blocked_user.blocked_until and blocked_user.blocked_until.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):
            raise HTTPException(
                status_code=403, detail="Tu cuenta está bloqueada temporalmente. Intenta más tarde."
            )
    # Verifica contraseña
    if not verify_password(request.password, user.password):
        if not blocked_user:
            blocked_user = BlockedEmail(
                email=request.email, failed_attempts=1
            )
            db.add(blocked_user)
        else:
            blocked_user.failed_attempts += 1
        # Define los máximos intentos y tiempo de bloqueo
        MAX_ATTEMPTS = 5
        BLOCK_TIME = timedelta(minutes=15)
        if blocked_user.failed_attempts >= MAX_ATTEMPTS:
            blocked_user.blocked_until = datetime.now(timezone.utc) + BLOCK_TIME
            db.commit()
            raise HTTPException(
                status_code=403, detail="Tu cuenta ha sido bloqueada temporalmente debido a intentos fallidos."
            )
        db.commit()
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")
    # Si el usuario tiene 2FA activado, requiere segundo paso
    if user.tfa_enabled:
        return {
            "status": "2fa_required",
            "message": "Se requiere autenticación de doble factor",
            "email": user.email
        }
    # Si login exitoso, limpia bloqueos
    if blocked_user:
        db.delete(blocked_user)
        db.commit()
    access_token = create_access_token(data={
        "user_id": user.user_id,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "email": user.email,
        "provider": user.provider,
        "tfa_enabled": user.tfa_enabled
    })
    return {
        "msg": "Login exitoso",
        "user_id": user.user_id,
        "access_token": access_token,
        "token_type": "bearer"
    }

# Login with Google
@router.post("/login-google")
async def login_google(request: GoogleLoginRequest, db: Session = Depends(get_db)):
    """
    Inicia sesión o registra un usuario con Google.
    """
    user = login_or_register_google(db, request.email, request.first_name)
    access_token = create_access_token(data={
        "user_id": user.user_id,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "email": user.email,
        "provider": user.provider,
        "tfa_enabled": user.tfa_enabled
    })
    return {"status": "success", "access_token": access_token, "token_type": "bearer"}

# Validate token
@router.get("/validate-token")
async def validate_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = decode_access_token(token)
        return {"status": "success", "message": "Token válido", "data": payload}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")

# Forgot password
@router.post("/forgot-password")
async def forgot_password(request: ForgotPasswordRequest, db: Session = Depends(get_db)):
    email = request.email
    user = db.query(User).filter_by(email=email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    try:
        reset_token = create_access_token(data={
        "user_id": user.user_id,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "email": user.email,
        "provider": user.provider,
        "tfa_enabled": user.tfa_enabled
    }, expires_delta=timedelta(minutes=10))
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
            subtype="html"
        )
        await fastmail.send_message(message)  # Descomenta si tienes fastmail configurado
        return {"status": "success", "message": "Enlace de restablecimiento enviado", "email": email}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al enviar el email: {str(e)}")

# Reset password
@router.post("/reset-password")
async def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):
    token = request.token
    new_password = request.new_password
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

    # Eliminar duplicado de login

@router.get("/blocked/{email}", response_model=BlockedEmailRead)
def get_blocked_email(email: str, db: Session = Depends(get_db)):
    blocked = db.query(BlockedEmail).filter_by(email=email).first()
    if not blocked:
        raise HTTPException(status_code=404, detail="email no bloqueado")
    return blocked

@router.get("/user-profile")
async def get_user_profile(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    """
    Devuelve los datos del perfil del usuario autenticado.
    """
    token = credentials.credentials
    try:
        payload = decode_access_token(token)
        email = payload.get("email")
        if not email:
            raise HTTPException(status_code=400, detail="Token inválido")
        user = db.query(User).filter_by(email=email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        # Si tienes Roadmap, descomenta la siguiente línea y el campo en la respuesta
        # roadmaps_count = db.query(Roadmap).filter_by(user_id_creador=user.user_id).count()
        return {
            "status": "success",
            "data": {
                "firstName": user.first_name,
                "lastName": user.last_name,
                "email": user.email,
                "credits": user.credits,
                # "roadmapsCreated": roadmaps_count,  # Descomenta si tienes Roadmap
                "provider": user.provider,
                "tfa_enabled": user.tfa_enabled,
            },
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")
##Conectar con la api q haga este endpoint
@router.get("/user-roadmaps")
async def user_roadmaps_placeholder():
    return {"status": "info", "message": "Endpoint en desarrollo"}

@router.put("/update-2fa")
async def update_2fa_status(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
    is_2fa_enabled: bool = Body(..., embed=True),
):
    """
    Actualiza el estado de la autenticación de doble factor (2FA) para el usuario autenticado.
    """
    token = credentials.credentials
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
            "data": {
                "tfa_enabled": user.tfa_enabled,
            },
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error al actualizar el estado de 2FA: {str(e)}")

# Modelo para actualizar usuario

@router.delete("/delete-user/{email}")
async def delete_user(
    email: str,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    """
    Eliminar un usuario y sus roadmaps asociados (si existieran).
    """
    token = credentials.credentials
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
        # Si tienes Roadmap, descomenta la siguiente línea
        # db.query(Roadmap).filter(Roadmap.user_id_creador == user_to_delete.user_id).delete(synchronize_session=False)
        db.delete(user_to_delete)
        db.commit()
        return {
            "status": "success",
            "message": "User deleted successfully",
            "deleted_user_email": email
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        db.rollback()
        print(f"Error al borrar usuario: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/update-user")
async def update_user(
    request: UserUpdateRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    try:
        token = credentials.credentials
        payload = decode_access_token(token)
        authenticated_email = payload.get("email")
        if not authenticated_email:
            raise HTTPException(status_code=400, detail="Token inválido")
        user = db.query(User).filter(User.email == authenticated_email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        # Prioriza los campos en inglés si existen, si no usa los de español
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

@router.get("/user-credits/{email}")
async def get_user_credits(
    email: str,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    """
    Consulta la cantidad de créditos de un usuario por email. Protegido por JWT.
    """
    token = credentials.credentials
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


@router.patch("/user-credits/{email}")
async def update_user_credits(
    email: str,
    request: CreditsUpdateRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    """
    Suma o resta créditos al usuario especificado por email. Protegido por JWT.
    """
    token = credentials.credentials
    try:
        decode_access_token(token)
        user = db.query(User).filter_by(email=email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        user.credits += request.amount
        if user.credits < 0:
            user.credits = 0  # No permitir créditos negativos
        db.commit()
        return {"status": "success", "email": email, "credits": user.credits}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")