
from sqlalchemy import Column, Integer, String, DateTime
from .base import Base
from datetime import datetime, timezone

class BlockedEmail(Base):
    __tablename__ = "correos_bloqueados"

    id = Column(Integer, primary_key=True, index=True)
    correo = Column(String, unique=True, nullable=False)
    fecha_bloqueo = Column(DateTime, default=datetime.now(timezone.utc))
    # Contador de intentos fallidos
    intentos_fallidos = Column(Integer, default=0)
    bloqueado_hasta = Column(DateTime, nullable=True)
    correos_login = Column(String, nullable=True)