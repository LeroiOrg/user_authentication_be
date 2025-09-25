from sqlalchemy import Column, Integer, String, Boolean
from .base import Base

class User(Base):
    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=True)
    provider = Column(String, nullable=True, default='local')
    credits = Column(Integer, nullable=False, default=0)
    tfa_enabled = Column(Boolean, nullable=False, default=False)