import os
import jwt
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi_mail import MessageSchema
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.models.user_model import User
from app.models.blocked_email import BlockedEmail
from app.models.verification_code import VerificationCode
from app.schemas.user_scheme import UserCreate, UserLogin, UserRead, BlockedEmailRead
from app.services.auth_service import (
    register_user, authenticate_user, is_email_blocked, save_verification_code, verify_code,
    get_password_hash, create_access_token, decode_access_token, verify_password, login_or_register_google
)
from app.services.email_service import fastmail
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import timedelta, datetime, timezone
from pydantic import BaseModel, EmailStr

router = APIRouter()
security = HTTPBearer()

SECRET_KEY = os.getenv("SECRET_KEY", "secret")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")

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

# Verify code
class EmailVerificationRequest(BaseModel):
    email: EmailStr
    code: str

@router.post("/verify-code")
async def verify_code_endpoint(request: EmailVerificationRequest, db: Session = Depends(get_db)):
    if verify_code(db, request.email, request.code):
        access_token = create_access_token(data={"sub": request.email})
        return {
            "status": "success",
            "message": "Código de verificación correcto",
            "access_token": access_token,
            "token_type": "bearer"
        }
    else:
        raise HTTPException(
            status_code=400,
            detail="Código de verificación incorrecto o expirado"
        )

# Register user
from pydantic import BaseModel, EmailStr

class UserRegistrationRequest(BaseModel):
    name: str
    last_name: str = ""
    email: EmailStr
    password: str = None
    provider: str = "email"

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
class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str

@router.post("/login")
async def login_user(request: UserLoginRequest, db: Session = Depends(get_db)):
    user_db = authenticate_user(db, request.email, request.password)
    if not user_db:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    access_token = create_access_token(data={"sub": user_db.correo})
    return {"msg": "Login exitoso", "user_id": user_db.id_usuario, "access_token": access_token, "token_type": "bearer"}

# Login with Google
class GoogleLoginRequest(BaseModel):
    email: str
    name: str

@router.post("/login-google")
async def login_google(request: GoogleLoginRequest, db: Session = Depends(get_db)):
    """
    Inicia sesión o registra un usuario con Google.
    """
    user = login_or_register_google(db, request.email, request.name)
    access_token = create_access_token(data={"sub": user.correo})
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
        reset_token = create_access_token(data={"sub": user.correo}, expires_delta=timedelta(minutes=10))
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
        # await fastmail.send_message(message)  # Descomenta si tienes fastmail configurado
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
        email = payload.get("sub")
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