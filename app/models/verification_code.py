from sqlalchemy import Column, Integer, String, DateTime
from .base import Base

class VerificationCode(Base):
    __tablename__ = "codigos"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, index=True, nullable=False)
    codigo = Column(String, nullable=False)
    expiracion = Column(DateTime, nullable=False)