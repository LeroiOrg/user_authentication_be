import os
import jwt
from fastapi import APIRouter, Depends, HTTPException, status, Request, Body
from fastapi_mail import MessageSchema
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.models.user_model import User
from app.models.blocked_email import BlockedEmail
from app.models.verification_code import VerificationCode
from app.schemas.user_scheme import UserCreate, UserLogin, UserRead, BlockedEmailRead, UserUpdateRequest, UserLoginRequest, GoogleLoginRequest, EmailVerificationRequest, UserRegistrationRequest
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

router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Check if email exists
@router.post("/check-email")
async def check_email(request: dict, db: Session = Depends(get_db)):
    email = request.get("email")
    user = db.query(User).filter_by(correo=email).first()
    return {"status": "success", "exists": user is not None}

# Send verification code
@router.post("/send-verification")
async def send_verification_email(request: dict, db: Session = Depends(get_db)):
    email = request.get("email")
    code = request.get("code")
    try:
        save_verification_code(db, email, code)
        message = MessageSchema(
            subject="Verificación de Correo - LEROI",
            recipients=[email],
            body=(
                f"<html>"
                f"<body style='font-family: Arial, sans-serif; text-align: center; margin: 0; padding: 40px;'>"
                f"<h1 style='font-size: 30px; font-weight: bold; color: #ffb923;'>Código de Verificación</h1>"
                f"<p style='font-size: 20px; color: #000000;'>Tu código de verificación es:</p>"
                f"<h2 style='font-size: 40px; color: #835bfc;'>{code}</h2>"
                f"<p style='font-size: 16px; color: #000000;'>Este código expirará en 5 minutos.</p>"
                f"<p style='font-size: 16px; color: #000000;'>Si no solicitaste este código, puedes ignorar este correo.</p>"
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
    blocked_user = db.query(BlockedEmail).filter_by(correo=request.email).first()
    if blocked_user:
        if blocked_user.bloqueado_hasta and blocked_user.bloqueado_hasta.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):
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
                correo=request.email, intentos_fallidos=1
            )
            db.add(blocked_user)
        else:
            blocked_user.intentos_fallidos += 1
        MAX_ATTEMPTS = 5
        BLOCK_TIME = timedelta(minutes=15)
        if blocked_user.intentos_fallidos >= MAX_ATTEMPTS:
            blocked_user.bloqueado_hasta = datetime.now(timezone.utc) + BLOCK_TIME
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
    blocked_user = db.query(BlockedEmail).filter_by(correo=request.email).first()
    if blocked_user:
        if blocked_user.bloqueado_hasta and blocked_user.bloqueado_hasta.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):
            raise HTTPException(
                status_code=403, detail="Tu cuenta está bloqueada temporalmente. Intenta más tarde."
            )
    if verify_code(db, request.email, request.code):
        if blocked_user:
            db.delete(blocked_user)
            db.commit()
        user = db.query(User).filter_by(correo=request.email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        access_token = create_access_token(data={
            "sub": user.correo,
            "nombre": user.nombre,
            "apellido": user.apellido,
            "correo": user.correo,
            "proveedor": user.proveedor,
            "id_usuario": user.id_usuario
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
                correo=request.email, intentos_fallidos=1
            )
            db.add(blocked_user)
        else:
            blocked_user.intentos_fallidos += 1
        MAX_ATTEMPTS = 5
        BLOCK_TIME = timedelta(minutes=15)
        if blocked_user.intentos_fallidos >= MAX_ATTEMPTS:
            blocked_user.bloqueado_hasta = datetime.now(timezone.utc) + BLOCK_TIME
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
        BlockedEmail.correo == request.email).first()
    if blocked_email:
        raise HTTPException(
            status_code=400, detail="Este correo está bloqueado y no puede registrarse.")
    # Hashea la contraseña si está presente
    hashed_password = get_password_hash(request.password) if request.password else None
    # Crea un nuevo objeto de usuario
    user = User(
        nombre=request.name,
        apellido=request.last_name if request.last_name else '',
        correo=request.email,
        contraseña=hashed_password,
        proveedor=request.provider,
        creditos=1000
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"status": "success", "message": "Usuario registrado correctamente"}

# Login
@router.post("/login")
async def login_user(request: UserLoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(correo=request.email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    if user.proveedor == "google":
        raise HTTPException(status_code=401, detail="Ya has iniciado sesión con Google")
    # Bloqueo por intentos fallidos
    blocked_user = db.query(BlockedEmail).filter_by(correo=request.email).first()
    if blocked_user:
        if blocked_user.bloqueado_hasta and blocked_user.bloqueado_hasta.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):
            raise HTTPException(
                status_code=403, detail="Tu cuenta está bloqueada temporalmente. Intenta más tarde."
            )
    # Verifica contraseña
    if not verify_password(request.password, user.contraseña):
        if not blocked_user:
            blocked_user = BlockedEmail(
                correo=request.email, intentos_fallidos=1
            )
            db.add(blocked_user)
        else:
            blocked_user.intentos_fallidos += 1
        # Define los máximos intentos y tiempo de bloqueo
        MAX_ATTEMPTS = 5
        BLOCK_TIME = timedelta(minutes=15)
        if blocked_user.intentos_fallidos >= MAX_ATTEMPTS:
            blocked_user.bloqueado_hasta = datetime.now(timezone.utc) + BLOCK_TIME
            db.commit()
            raise HTTPException(
                status_code=403, detail="Tu cuenta ha sido bloqueada temporalmente debido a intentos fallidos."
            )
        db.commit()
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")
    # Si el usuario tiene 2FA activado, requiere segundo paso
    if user.TFA_enabled:
        return {
            "status": "2fa_required",
            "message": "Se requiere autenticación de doble factor",
            "email": user.correo
        }
    # Si login exitoso, limpia bloqueos
    if blocked_user:
        db.delete(blocked_user)
        db.commit()
    access_token = create_access_token(data={
        "id_usuario": user.id_usuario,
        "nombre": user.nombre,
        "apellido": user.apellido,
        "correo": user.correo,
        "proveedor": user.proveedor,
        "TFA_enabled": user.TFA_enabled
    })
    return {
        "msg": "Login exitoso",
        "user_id": user.id_usuario,
        "access_token": access_token,
        "token_type": "bearer"
    }

# Login with Google
@router.post("/login-google")
async def login_google(request: GoogleLoginRequest, db: Session = Depends(get_db)):
    """
    Inicia sesión o registra un usuario con Google.
    """
    user = login_or_register_google(db, request.email, request.name)
    access_token = create_access_token(data={
        "id_usuario": user.id_usuario,
        "nombre": user.nombre,
        "apellido": user.apellido,
        "correo": user.correo,
        "proveedor": user.proveedor,
        "TFA_enabled": user.TFA_enabled
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
async def forgot_password(request: dict, db: Session = Depends(get_db)):
    email = request.get("email")
    user = db.query(User).filter_by(correo=email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    try:
        reset_token = create_access_token(data={
            "id_usuario": user.id_usuario,
            "nombre": user.nombre,
            "apellido": user.apellido,
            "correo": user.correo,
            "proveedor": user.proveedor,
            "TFA_enabled": user.TFA_enabled
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
                f"<p style='font-size: 16px; color: #000000;'>Si no solicitaste este cambio, puedes ignorar este correo.</p>"
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
async def reset_password(request: dict, db: Session = Depends(get_db)):
    token = request.get("token")
    new_password = request.get("new_password")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("correo")
        if email is None:
            raise HTTPException(status_code=400, detail="Token inválido")
        user = db.query(User).filter_by(correo=email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        user.contraseña = get_password_hash(new_password)
        db.commit()
        return {"status": "success", "message": "Contraseña cambiada correctamente"}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="El token ha expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=400, detail="Token inválido")

    # Eliminar duplicado de login

@router.get("/blocked/{correo}", response_model=BlockedEmailRead)
def get_blocked_email(correo: str, db: Session = Depends(get_db)):
    blocked = db.query(BlockedEmail).filter_by(correo=correo).first()
    if not blocked:
        raise HTTPException(status_code=404, detail="Correo no bloqueado")
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
        email = payload.get("correo")
        if not email:
            raise HTTPException(status_code=400, detail="Token inválido")
        user = db.query(User).filter_by(correo=email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        # Si tienes Roadmap, descomenta la siguiente línea y el campo en la respuesta
        # roadmaps_count = db.query(Roadmap).filter_by(id_usuario_creador=user.id_usuario).count()
        return {
            "status": "success",
            "data": {
                "firstName": user.nombre,
                "lastName": user.apellido,
                "email": user.correo,
                "credits": user.creditos,
                # "roadmapsCreated": roadmaps_count,  # Descomenta si tienes Roadmap
                "provider": user.proveedor,
                "TFA_enabled": user.TFA_enabled,
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
        email = payload.get("correo")
        if not email:
            raise HTTPException(status_code=400, detail="Token inválido")
        user = db.query(User).filter_by(correo=email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        user.TFA_enabled = is_2fa_enabled
        db.commit()
        return {
            "status": "success",
            "message": "Estado de 2FA actualizado correctamente",
            "data": {
                "TFA_enabled": user.TFA_enabled,
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
        authenticated_email = payload.get("correo")
        user_role = payload.get("role") if "role" in payload else None
        if not authenticated_email:
            raise HTTPException(status_code=400, detail="Invalid token")
        if user_role != "admin" and authenticated_email != email:
            raise HTTPException(status_code=403, detail="Unauthorized action")
        user_to_delete = db.query(User).filter_by(correo=email).first()
        if not user_to_delete:
            raise HTTPException(status_code=404, detail="User not found")
        # Si tienes Roadmap, descomenta la siguiente línea
        # db.query(Roadmap).filter(Roadmap.id_usuario_creador == user_to_delete.id_usuario).delete(synchronize_session=False)
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
        authenticated_email = payload.get("correo")
        if not authenticated_email:
            raise HTTPException(status_code=400, detail="Token inválido")
        user = db.query(User).filter(User.correo == authenticated_email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        # Prioriza los campos en inglés si existen, si no usa los de español
        if request.name or request.nombre:
            user.nombre = request.name if request.name is not None else request.nombre
        if request.last_name or request.apellido:
            user.apellido = request.last_name if request.last_name is not None else request.apellido
        if request.email or request.correo:
            user.correo = request.email if request.email is not None else request.correo
        if request.provider or request.proveedor:
            user.proveedor = request.provider if request.provider is not None else request.proveedor
        db.commit()
        return {
            "status": "success",
            "message": "Datos de usuario actualizados correctamente",
            "data": {
                "nombre": user.nombre,
                "apellido": user.apellido,
                "correo": user.correo,
                "proveedor": user.proveedor,
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
    Consulta la cantidad de créditos de un usuario por correo. Protegido por JWT.
    """
    token = credentials.credentials
    try:
        decode_access_token(token)
        user = db.query(User).filter_by(correo=email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        return {"status": "success", "email": email, "credits": user.creditos}
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
    Suma o resta créditos al usuario especificado por correo. Protegido por JWT.
    """
    token = credentials.credentials
    try:
        decode_access_token(token)
        user = db.query(User).filter_by(correo=email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        user.creditos += request.amount
        if user.creditos < 0:
            user.creditos = 0  # No permitir créditos negativos
        db.commit()
        return {"status": "success", "email": email, "credits": user.creditos}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")