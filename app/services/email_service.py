import os
from email.message import EmailMessage
from typing import Iterable
from dotenv import load_dotenv
import aiosmtplib

# Cargar variables de entorno desde .env local (útil fuera de Docker)
env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '..', '.env')
load_dotenv(env_path)

MAIL_USERNAME = os.getenv('MAIL_USERNAME')
_raw_password = os.getenv('MAIL_PASSWORD')
MAIL_PASSWORD = None
if _raw_password is not None:
    # Quitar comillas y espacios extras; para Gmail, los app passwords no llevan espacios
    cleaned = _raw_password.strip().strip('"').strip()
    # Si es Gmail, remover espacios internos comunes en app passwords
    MAIL_PASSWORD = cleaned.replace(' ', '') if 'gmail' in os.getenv('MAIL_SERVER', '').lower() else cleaned
MAIL_FROM = os.getenv('MAIL_FROM', MAIL_USERNAME)
MAIL_PORT = int(os.getenv('MAIL_PORT', '587'))
MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')


async def send_email_html(subject: str, recipients: Iterable[str], html_body: str, plain_fallback: str | None = None) -> None:
    """
    Envía un correo HTML de forma asíncrona usando SMTP.

    - Usa STARTTLS por defecto en el puerto 587.
    - Si el puerto es 465, usa TLS directo.
    - Requiere las variables de entorno: MAIL_USERNAME, MAIL_PASSWORD, MAIL_FROM (opcional), MAIL_PORT, MAIL_SERVER.
    """
    if not MAIL_USERNAME or not MAIL_PASSWORD:
        raise RuntimeError("MAIL_USERNAME/MAIL_PASSWORD no configurados en el entorno")

    if not recipients:
        raise ValueError("recipients no puede estar vacío")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = MAIL_FROM or MAIL_USERNAME
    msg["To"] = ", ".join(recipients)

    # Contenido en texto plano (fallback)
    if not plain_fallback:
        plain_fallback = "Este correo contiene contenido HTML. Si no lo ves, habilita HTML en tu cliente."
    msg.set_content(plain_fallback)

    # Alternativa HTML
    msg.add_alternative(html_body, subtype="html")

    # Conexión segura según puerto
    use_tls_direct = MAIL_PORT == 465

    if use_tls_direct:
        # TLS desde el inicio (p. ej., 465)
        await aiosmtplib.send(
            msg,
            hostname=MAIL_SERVER,
            port=MAIL_PORT,
            username=MAIL_USERNAME,
            password=MAIL_PASSWORD,
            use_tls=True,
        )
    else:
        # STARTTLS (p. ej., 587) - delega a aiosmtplib para iniciar TLS una sola vez
        await aiosmtplib.send(
            msg,
            hostname=MAIL_SERVER,
            port=MAIL_PORT,
            username=MAIL_USERNAME,
            password=MAIL_PASSWORD,
            start_tls=True,
        )
