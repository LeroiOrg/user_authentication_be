from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api import auth_routes

app = FastAPI(title="Users authentication service")
app.include_router(auth_routes.router, prefix="/users_authentication_path", tags=["users_authentication"])

app.add_middleware(
	CORSMiddleware,
	allow_origins=["*"],
	allow_credentials=True,
	allow_methods=["*"],
	allow_headers=["*"],
)

if __name__ == "__main__":
	import uvicorn
	uvicorn.run(app, host="0.0.0.0", port=8000)
