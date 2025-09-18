# auth_service.py
# Servicio para la autenticación de usuarios

class AuthService:
    def authenticate_user(self, username: str, password: str) -> bool:
        # Lógica de autenticación (placeholder)
        # Retorna True si la autenticación es exitosa, False en caso contrario
        return username == "admin" and password == "admin"
