
from sqlalchemy import Column, Integer, String, DateTime
from .base import Base
from datetime import datetime, timezone

class BlockedEmail(Base):
    __tablename__ = "blocked_emails"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, nullable=False)
    blocked_at = Column(DateTime, default=datetime.now(timezone.utc))
    failed_attempts = Column(Integer, default=0)
    blocked_until = Column(DateTime, nullable=True)
    login_emails = Column(String, nullable=True)
