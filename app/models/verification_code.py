from sqlalchemy import Column, Integer, String, DateTime
from .base import Base

class VerificationCode(Base):
    __tablename__ = "verification_codes"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, index=True, nullable=False)
    code = Column(String, nullable=False)
    expiration = Column(DateTime, nullable=False)