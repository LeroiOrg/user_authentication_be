from app.models.base import Base
from app.models.user_model import User
from app.models.verification_code import VerificationCode
from app.models.blocked_email import BlockedEmail
from app.db.session import engine

# Crea todas las tablas en la base de datos
Base.metadata.create_all(bind=engine)
print("Tablas creadas correctamente.")
