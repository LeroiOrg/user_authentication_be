from fastapi_mail import FastMail, ConnectionConfig
import os
from dotenv import load_dotenv

# Cargar variables de entorno
env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '..', '.env')
load_dotenv(env_path)

email_config = ConnectionConfig(
    MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
    MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),
    MAIL_FROM=os.getenv('MAIL_FROM'),
    MAIL_PORT=int(os.getenv('MAIL_PORT')),
    MAIL_SERVER=os.getenv('MAIL_SERVER'),
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True
)

fastmail = FastMail(email_config)
