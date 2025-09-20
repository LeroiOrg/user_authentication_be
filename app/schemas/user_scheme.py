from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

class UserCreate(BaseModel):
    nombre: str
    apellido: Optional[str] = None
    correo: EmailStr
    contraseña: Optional[str] = None
    proveedor: Optional[str] = "local"

class UserRead(BaseModel):
    id_usuario: int
    nombre: str
    apellido: Optional[str] = None
    correo: EmailStr
    proveedor: Optional[str]
    creditos: int
    TFA_enabled: bool

    class Config:
        orm_mode = True

class UserLogin(BaseModel):
    correo: EmailStr
    contraseña: str

class BlockedEmailRead(BaseModel):
    id: int
    correo: EmailStr
    fecha_bloqueo: datetime
    intentos_fallidos: int
    bloqueado_hasta: Optional[datetime]
    correos_login: Optional[str]

    class Config:
        orm_mode = True

class UserUpdateRequest(BaseModel):
    nombre: Optional[str] = None
    name: Optional[str] = None
    apellido: Optional[str] = None
    last_name: Optional[str] = None
    correo: Optional[EmailStr] = None
    email: Optional[EmailStr] = None
    proveedor: Optional[str] = None
    provider: Optional[str] = None

    class Config:
        allow_population_by_field_name = True

class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str

class GoogleLoginRequest(BaseModel):
    email: str
    name: str

class EmailVerificationRequest(BaseModel):
    email: EmailStr
    code: str

class UserRegistrationRequest(BaseModel):
    name: str
    last_name: str = ""
    email: EmailStr
    password: str = None
    provider: str = "email"

class CheckEmailRequest(BaseModel):
    email: EmailStr
    class Config:
        schema_extra = {
            "example": {
                "email": "user@example.com"
            }
        }

class SendVerificationRequest(BaseModel):
    email: EmailStr
    code: str
    class Config:
        schema_extra = {
            "example": {
                "email": "user@example.com",
                "code": "123456"
            }
        }

class ForgotPasswordRequest(BaseModel):
    email: EmailStr
    class Config:
        schema_extra = {
            "example": {
                "email": "user@example.com"
            }
        }

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str
    class Config:
        schema_extra = {
            "example": {
                "token": "<jwt_token>",
                "new_password": "newStrongPassword123"
            }
        }