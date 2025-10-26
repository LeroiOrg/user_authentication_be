import jwt
import os
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from app.models.user_model import User
from app.models.blocked_email import BlockedEmail
from app.models.verification_code import VerificationCode
from app.schemas.user_scheme import UserCreate

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode["exp"] = expire
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str):
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

def is_email_blocked(db: Session, correo: str) -> bool:
    blocked = db.query(BlockedEmail).filter_by(correo=correo).first()
    if blocked and blocked.bloqueado_hasta:
        if blocked.bloqueado_hasta.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):
            return True
    return False

def register_user(db: Session, user: UserCreate):
    if db.query(User).filter_by(correo=user.correo).first():
        raise Exception("El correo ya está registrado")
    hashed_password = get_password_hash(user.contraseña)
    db_user = User(
        nombre=user.nombre,
        apellido=user.apellido or '',
        correo=user.correo,
        contraseña=hashed_password,
        proveedor=user.proveedor,
        creditos=1000
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def authenticate_user(db: Session, correo: str, contraseña: str):
    user = db.query(User).filter_by(correo=correo).first()
    if not user:
        return None
    if not verify_password(contraseña, user.contraseña):
        # Aquí puedes incrementar intentos_fallidos en BlockedEmail si lo deseas
        return None
    return user

def save_verification_code(db: Session, email: str, code: str, minutes_expire: int = 5):
    expiration = datetime.now(timezone.utc) + timedelta(minutes=minutes_expire)
    db_code = VerificationCode(email=email, code=code, expiration=expiration)
    db.add(db_code)
    db.commit()
    return db_code

def verify_code(db: Session, email: str, code: str) -> bool:
    db_code = db.query(VerificationCode).filter_by(email=email, code=code).first()
    if db_code and db_code.expiration.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):
        db.delete(db_code)
        db.commit()
        return True
    return False

def login_or_register_google(db: Session, email: str, name: str):
    # Use current English model fields
    user = db.query(User).filter_by(email=email).first()
    if not user:
        user = User(
            first_name=name,
            last_name='',
            email=email,
            password=None,
            provider="google",
            credits=1000,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    return user