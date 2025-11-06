"""import os
import json
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.models.user_model import User

# Solo habilita Pub/Sub si están definidas las variables de entorno
GOOGLE_PROJECT_ID = os.getenv("PROJECT_ID")
SUBSCRIPTION_ID = os.getenv("SUBSCRIPTION_ID")

PUBSUB_ENABLED = bool(GOOGLE_PROJECT_ID and SUBSCRIPTION_ID)

# Definimos pubsub_v1 solo si está habilitado
pubsub_v1 = None
FlowControl = None
if PUBSUB_ENABLED:
    from google.cloud import pubsub_v1
    from google.cloud.pubsub_v1.types import FlowControl

def process_message(message):
    try:
        data = json.loads(message.data.decode("utf-8"))
        event = data.get("event")
        payload = data.get("data", {})

        print(f"Mensaje recibido: {data}")

        if event in ("payment_approved", "payment_status_changed") and payload.get("status") == "approved":
            email = payload["email"]
            credits = int(payload["credits"])
            update_user_credits_in_db(email, credits)
            
        elif event == "credit_update":
            email = payload.get("email")
            credits_change = int(payload.get("credits_change", 0))
            update_user_credits_in_db(email, credits_change)

        if PUBSUB_ENABLED:
            message.ack()
    except Exception as e:
        print(f"Error procesando mensaje Pub/Sub: {e}")
        if PUBSUB_ENABLED:
            message.nack()


def update_user_credits_in_db(email: str, credits: int):
    db: Session = SessionLocal()
    try:
        user = db.query(User).filter_by(email=email).first()
        if user:
            user.credits += credits
            db.commit()
            print(f"Créditos actualizados para {email}: +{credits}")
        else:
            print(f"Usuario {email} no encontrado en la base de datos.")
    except Exception as e:
        db.rollback()
        print(f"Error actualizando DB: {e}")
    finally:
        db.close()


def start_subscriber():
    if not PUBSUB_ENABLED:
        print("⚠️ Pub/Sub listener ignorado. No se usarán credenciales de Google Cloud.")
        return  # TERMINA AQUÍ si no hay variables

    subscriber = pubsub_v1.SubscriberClient()
    subscription_path = subscriber.subscription_path(GOOGLE_PROJECT_ID, SUBSCRIPTION_ID)
    flow_control = FlowControl(max_messages=1)

    def callback(message):
        print("Mensaje recibido en callback")
        process_message(message)

    print(f"Escuchando mensajes en {subscription_path} ...")
    future = subscriber.subscribe(
        subscription_path,
        callback=callback,
        flow_control=flow_control
    )

    try:
        future.result()
    except KeyboardInterrupt:
        future.cancel()"""
import os
import json
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.models.user_model import User

PUBSUB_ENABLED = False

def process_message(message):
    return

def start_subscriber():
    print("⚠️ Pub/Sub listener deshabilitado. Función no hace nada.")
    return

def update_user_credits_in_db(email: str, credits: int):
    db: Session = SessionLocal()
    try:
        user = db.query(User).filter_by(email=email).first()
        if user:
            user.credits += credits
            db.commit()
            print(f"Créditos actualizados para {email}: +{credits}")
        else:
            print(f"Usuario {email} no encontrado en la base de datos.")
    except Exception as e:
        db.rollback()
        print(f"Error actualizando DB: {e}")
    finally:
        db.close()