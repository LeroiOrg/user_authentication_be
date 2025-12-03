from sqlalchemy import Column, Integer, String, Boolean
from .base import Base

class User(Base):
    __tablename__ = "users"

    id_usuario = Column(Integer, primary_key=True, index=True)
    nombre = Column(String, nullable=False)
    apellido = Column(String, nullable=True)
    correo = Column(String, unique=True, index=True, nullable=False)
    contraseña = Column(String, nullable=True)
    proveedor = Column(String, nullable=True, default='local')
    creditos = Column(Integer, nullable=False, default=0)
    tfa_enabled = Column(Boolean, nullable=False, default=False)
