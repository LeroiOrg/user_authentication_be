import json, os, threading
from google.cloud import pubsub_v1
from google.cloud.pubsub_v1.types import FlowControl
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.models.user_model import User

PROJECT_ID = os.getenv("PROJECT_ID")
SUBSCRIPTION_ID = os.getenv("SUBSCRIPTION_ID")


def process_message(message):
    try:
        data = json.loads(message.data.decode("utf-8"))
        event = data.get("event")
        payload = data.get("data", {})

        print(f" Mensaje recibido: {data}")

        if event in ("payment_approved", "payment_status_changed") and payload.get("status") == "approved":
            email = payload["email"]
            credits = int(payload["credits"])
            update_user_credits_in_db(email, credits)
            
        elif event == "credit_update":
            email = payload.get("email")
            credits_change = int(payload.get("credits_change", 0))
            update_user_credits_in_db(email, credits_change)

        message.ack()
    except Exception as e:
        print(f" Error procesando mensaje Pub/Sub: {e}")
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
        print(f" Error actualizando DB: {e}")
    finally:
        db.close()

def start_subscriber():
    subscriber = pubsub_v1.SubscriberClient()
    subscription_path = subscriber.subscription_path(PROJECT_ID, SUBSCRIPTION_ID)
    flow_control = FlowControl(max_messages=1)

    def callback(message):
        print(f"📩 Mensaje recibido en callback")
        process_message(message)

    print(f"🚀 Escuchando mensajes en {subscription_path} ...")
    future = subscriber.subscribe(
        subscription_path,
        callback=callback,
        flow_control=flow_control
    )

    try:
        future.result()
    except KeyboardInterrupt:
        future.cancel()

if __name__ == "__main__":
    start_subscriber()
