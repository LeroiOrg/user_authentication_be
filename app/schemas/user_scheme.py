# from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field


class UserCreate(BaseModel):
    first_name: str = Field(..., alias="nombre")
    last_name: Optional[str] = Field(None, alias="apellido")
    email: EmailStr = Field(..., alias="correo")
    password: Optional[str] = Field(None, alias="contraseña")
    provider: Optional[str] = Field("local", alias="proveedor")

    class Config:
        allow_population_by_field_name = True


class UserRead(BaseModel):
    user_id: int = Field(..., alias="id_usuario")
    first_name: str = Field(..., alias="nombre")
    last_name: Optional[str] = Field(None, alias="apellido")
    email: EmailStr = Field(..., alias="correo")
    provider: Optional[str] = Field(..., alias="proveedor")
    credits: int = Field(..., alias="creditos")
    tfa_enabled: bool = Field(..., alias="TFA_enabled")

    class Config:
        orm_mode = True
        allow_population_by_field_name = True


class UserLogin(BaseModel):
    email: EmailStr = Field(..., alias="correo")
    password: str = Field(..., alias="contraseña")

    class Config:
        allow_population_by_field_name = True


class BlockedEmailRead(BaseModel):
    id: int
    email: EmailStr = Field(..., alias="correo")
    blocked_at: datetime = Field(..., alias="fecha_bloqueo")
    failed_attempts: int = Field(..., alias="intentos_fallidos")
    blocked_until: Optional[datetime] = Field(None, alias="bloqueado_hasta")
    login_emails: Optional[str] = Field(None, alias="correos_login")

    class Config:
        orm_mode = True
        allow_population_by_field_name = True


class UserUpdateRequest(BaseModel):
    first_name: Optional[str] = Field(None, alias="nombre")
    last_name: Optional[str] = Field(None, alias="apellido")
    email: Optional[EmailStr] = Field(None, alias="correo")
    provider: Optional[str] = Field(None, alias="proveedor")

    class Config:
        allow_population_by_field_name = True


class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str


class GoogleLoginRequest(BaseModel):
    email: EmailStr
    name: str


class EmailVerificationRequest(BaseModel):
    email: EmailStr
    code: str


class UserRegistrationRequest(BaseModel):
    first_name: str = Field(..., alias="name")
    last_name: Optional[str] = Field("", alias="last_name")
    email: EmailStr
    password: Optional[str] = None
    provider: str = "email"

    class Config:
        allow_population_by_field_name = True


class CheckEmailRequest(BaseModel):
    email: EmailStr

    class Config:
        schema_extra = {
            "example": {"email": "user@example.com"}
        }


class SendVerificationRequest(BaseModel):
    email: EmailStr
    code: str

    class Config:
        schema_extra = {
            "example": {"email": "user@example.com", "code": "123456"}
        }


class ForgotPasswordRequest(BaseModel):
    email: EmailStr

    class Config:
        schema_extra = {
            "example": {"email": "user@example.com"}
        }


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

    class Config:
        schema_extra = {
            "example": {"token": "<jwt_token>", "new_password": "newStrongPassword123"}
        }
