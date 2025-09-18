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