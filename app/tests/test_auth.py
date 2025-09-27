
import sys
import os
import datetime
# Agrega la raíz del proyecto al sys.path para que 'app' sea importable al ejecutar pytest directamente
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
import pytest
from app.main import app
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
client = TestClient(app)


# Mock global para que verify_password siempre devuelva True en todos los tests
@pytest.fixture(autouse=True)
def always_verify_password_true():
    # Parchear tanto en el servicio base como en el handler (que hace import por nombre)
    with patch("app.services.auth_service.verify_password", return_value=True), \
         patch("app.services.auth_handlers.verify_password", return_value=True):
        yield

# Mock user data
mock_user = {
    "user_id": 1,
    "first_name": "Test",
    "last_name": "User",
    "email": "testuser@example.com",
    "provider": "email",
    "credits": 1000,
    "tfa_enabled": False,
    "password": "hashedpass"
}

@pytest.fixture
def mock_db_session():
    with patch("app.api.auth_routes.SessionLocal") as mock_session_local:
        mock_session = MagicMock()
        mock_session_local.return_value = mock_session
        yield mock_session

@patch("app.api.auth_routes.User")
def test_register_user(mock_user_model, mock_db_session):
    mock_db_session.query.return_value.filter.return_value.first.return_value = None
    mock_db_session.query.return_value.filter_by.return_value.first.return_value = None
    mock_db_session.add.return_value = None
    mock_db_session.commit.return_value = None
    mock_db_session.refresh.return_value = None
    response = client.post("/users_authentication_path/register", json={
        "name": "Test",
        "last_name": "User",
        "email": "testuser@example.com",
        "password": "testpass123",
        "provider": "email"
    })
    assert response.status_code == 200
    assert response.json()["status"] == "success"

def test_login_user(mock_db_session):
    user_instance = MagicMock(**mock_user)
    # Asegurar atributos esperados por la API en inglés
    user_instance.password = mock_user["password"]
    user_instance.provider = mock_user["provider"]
    user_instance.tfa_enabled = False
    user_instance.user_id = mock_user["user_id"]
    user_instance.first_name = mock_user["first_name"]
    user_instance.last_name = mock_user["last_name"]
    user_instance.email = mock_user["email"]
    # El primer llamado es para User, el segundo para BlockedEmail
    mock_db_session.query.return_value.filter_by.return_value.first.side_effect = [user_instance, None]
    response = client.post("/users_authentication_path/login", json={
        "email": "testuser@example.com",
        "password": "testpass123"
    })
    assert response.status_code == 200
    assert "access_token" in response.json()

@patch("app.api.auth_routes.User")
def test_forgot_password(mock_user_model, mock_db_session):
    user_instance = MagicMock(**mock_user)
    user_instance.user_id = mock_user["user_id"]
    user_instance.first_name = mock_user["first_name"]
    user_instance.last_name = mock_user["last_name"]
    user_instance.email = mock_user["email"]
    user_instance.provider = mock_user["provider"]
    user_instance.tfa_enabled = False
    mock_db_session.query.return_value.filter_by.return_value.first.return_value = user_instance
    with patch("app.services.auth_handlers.fastmail.send_message", return_value=None):
        with patch("app.services.auth_handlers.create_access_token", return_value="token123"):
            response = client.post("/users_authentication_path/forgot-password", json={
                "email": "testuser@example.com"
            })
    assert response.status_code == 200
    assert response.json()["status"] == "success"

def test_update_user(mock_db_session):
    # Simula usuario existente
    user_instance = MagicMock(**mock_user)
    user_instance.user_id = mock_user["user_id"]
    user_instance.first_name = mock_user["first_name"]
    user_instance.last_name = mock_user["last_name"]
    user_instance.email = mock_user["email"]
    user_instance.provider = mock_user["provider"]
    user_instance.tfa_enabled = False
    # Mock para búsqueda de usuario
    mock_db_session.query.return_value.filter.return_value.first.return_value = user_instance
    # Mock token JWT
    token = "fake.jwt.token"
    with patch("app.services.auth_handlers.decode_access_token", return_value={"email": "testuser@example.com"}):
        headers = {"Authorization": f"Bearer {token}"}
        response = client.put("/users_authentication_path/update-user", json={"first_name": "NuevoNombre"}, headers=headers)
    assert response.status_code == 200
    assert response.json()["status"] == "success"

def test_delete_user(mock_db_session):
    # Simula usuario existente
    user_instance = MagicMock(**mock_user)
    user_instance.user_id = mock_user["user_id"]
    user_instance.first_name = mock_user["first_name"]
    user_instance.last_name = mock_user["last_name"]
    user_instance.email = mock_user["email"]
    user_instance.provider = mock_user["provider"]
    user_instance.tfa_enabled = False
    # Mock para búsqueda de usuario
    mock_db_session.query.return_value.filter_by.return_value.first.return_value = user_instance
    # Mock token JWT con rol admin
    token = "fake.jwt.token"
    with patch("app.services.auth_handlers.decode_access_token", return_value={"email": "testuser@example.com", "role": "admin"}):
        headers = {"Authorization": f"Bearer {token}"}
        response = client.delete(f"/users_authentication_path/delete-user/{user_instance.email}", headers=headers)
    assert response.status_code == 200
    assert response.json()["status"] == "success"
