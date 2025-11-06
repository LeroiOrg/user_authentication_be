from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api import auth_routes
import threading
from app.pubsub.subscriber import start_subscriber, PUBSUB_ENABLED

app = FastAPI(title="Users authentication service")
app.include_router(auth_routes.router, prefix="/users_authentication_path", tags=["users_authentication"])

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup_event():
    if PUBSUB_ENABLED:
        thread = threading.Thread(target=start_subscriber, daemon=True)
        thread.start()
        print("Servicio iniciado con Pub/Sub listener activo.")
    else:
        print("⚠️ Pub/Sub listener ignorado: variables de entorno no definidas o credenciales no disponibles.")


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
