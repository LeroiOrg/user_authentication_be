from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api import auth_routes
import os
import threading
# Importamos el subscriber que vamos a crear
from app.pubsub.subscriber import start_subscriber

app = FastAPI(title="Users authentication service")
app.include_router(auth_routes.router, prefix="/users_authentication_path", tags=["users_authentication"])

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

#@app.on_event("startup")
#def startup_event():
#    """
#    Cuando se inicie el servicio, también se lanza el hilo del subscriber Pub/Sub.
#    """
#    thread = threading.Thread(target=start_subscriber, daemon=True)
#    thread.start()
#    print(" Servicio iniciado con Pub/Sub listener activo.")
    
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))  
    uvicorn.run(app, host="0.0.0.0", port=port)
