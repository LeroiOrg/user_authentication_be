import os
import jwt
from fastapi import APIRouter, Depends, HTTPException, status, Request, Body
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.models.user_model import User
from app.models.blocked_email import BlockedEmail
from app.models.verification_code import VerificationCode
from app.schemas.user_scheme import (
    UserCreate,
    UserLogin,
    UserRead,
    BlockedEmailRead,
    UserUpdateRequest,
    UserLoginRequest,
    GoogleLoginRequest,
    EmailVerificationRequest,
    UserRegistrationRequest,
    CheckEmailRequest,
    SendVerificationRequest,
    ForgotPasswordRequest,
    ResetPasswordRequest,
)
from app.schemas.credits_scheme import CreditsUpdateRequest
from app.services.auth_service import create_access_token, decode_access_token, login_or_register_google
from app.services.auth_handlers import (
    check_email_exists,
    send_verification_email as svc_send_verification_email,
    verify_code_for_registration as svc_verify_code_for_registration,
    verify_2fa_code as svc_verify_2fa_code,
    register_user as svc_register_user,
    login_user as svc_login_user,
    validate_token as svc_validate_token,
    forgot_password as svc_forgot_password,
    reset_password as svc_reset_password,
    get_blocked_email as svc_get_blocked_email,
    get_user_profile as svc_get_user_profile,
    update_2fa_status as svc_update_2fa_status,
    delete_user as svc_delete_user,
    update_user as svc_update_user,
    get_user_credits as svc_get_user_credits,
    update_user_credits as svc_update_user_credits,
)
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import timedelta, datetime, timezone
from pydantic import BaseModel, EmailStr

router = APIRouter()
security = HTTPBearer()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Check if email exists
@router.post("/check-email")
async def check_email(request: CheckEmailRequest, db: Session = Depends(get_db)):
    return check_email_exists(db, request.email)

# Send verification code
@router.post("/send-verification")
async def send_verification_email(request: SendVerificationRequest, db: Session = Depends(get_db)):
    return await svc_send_verification_email(db, request.email, request.code)


# Verificación de código para registro (solo valida el código, no busca usuario)
@router.post("/verify-code")
async def verify_code_endpoint(request: EmailVerificationRequest, db: Session = Depends(get_db)):
    return svc_verify_code_for_registration(db, request.email, request.code)

# Verificación de código para 2FA (requiere usuario y devuelve token)
@router.post("/verify-2fa-code")
async def verify_2fa_code(request: EmailVerificationRequest, db: Session = Depends(get_db)):
    return svc_verify_2fa_code(db, request.email, request.code)

# Register user
@router.post("/register")
async def register_user(request: UserRegistrationRequest, db: Session = Depends(get_db)):
    return svc_register_user(db, request.first_name, request.last_name, request.email, request.password, request.provider)

# Login
@router.post("/login")
async def login_user(request: UserLoginRequest, db: Session = Depends(get_db)):
    return svc_login_user(db, request.email, request.password)

# Login with Google
@router.post("/login-google")
async def login_google(request: GoogleLoginRequest, db: Session = Depends(get_db)):
    from app.services.auth_handlers import login_with_google as svc_login_with_google
    # GoogleLoginRequest defines 'name'; service expects (email, first_name)
    return svc_login_with_google(db, request.email, request.name)

# Validate token
@router.get("/validate-token")
async def validate_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    return svc_validate_token(token)

# Forgot password
@router.post("/forgot-password")
async def forgot_password(request: ForgotPasswordRequest, db: Session = Depends(get_db)):
    return await svc_forgot_password(db, request.email)

# Reset password
@router.post("/reset-password")
async def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):
    return svc_reset_password(db, request.token, request.new_password)

    # Eliminar duplicado de login

@router.get("/blocked/{email}", response_model=BlockedEmailRead)
def get_blocked_email(email: str, db: Session = Depends(get_db)):
    return svc_get_blocked_email(db, email)

@router.get("/user-profile")
async def get_user_profile(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    token = credentials.credentials
    return svc_get_user_profile(token, db)
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
    token = credentials.credentials
    return svc_update_2fa_status(token, db, is_2fa_enabled)

# Modelo para actualizar usuario

@router.delete("/delete-user/{email}")
async def delete_user(
    email: str,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    token = credentials.credentials
    return svc_delete_user(token, db, email)

@router.put("/update-user")
async def update_user(
    request: UserUpdateRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    token = credentials.credentials
    return svc_update_user(token, db, request)

@router.get("/user-credits/{email}")
async def get_user_credits(
    email: str,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    token = credentials.credentials
    return svc_get_user_credits(token, db, email)


@router.patch("/user-credits/{email}")
async def update_user_credits(
    email: str,
    request: CreditsUpdateRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    token = credentials.credentials
    return svc_update_user_credits(token, db, email, request.amount)