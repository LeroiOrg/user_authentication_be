
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
    with patch("app.services.auth_service.verify_password", return_value=True):
        yield

# Mock user data
mock_user = {
    "id_usuario": 1,
    "nombre": "Test",
    "apellido": "User",
    "correo": "testuser@example.com",
    "proveedor": "email",
    "creditos": 1000,
    "TFA_enabled": False,
    "contraseña": "hashedpass"
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
    response = client.post("/register", json={
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
    user_instance.contraseña = "hashedpass"
    user_instance.proveedor = "email"
    user_instance.TFA_enabled = False
    user_instance.id_usuario = 1
    user_instance.nombre = "Test"
    user_instance.apellido = "User"
    user_instance.correo = "testuser@example.com"
    # El primer llamado es para User, el segundo para BlockedEmail
    mock_db_session.query.return_value.filter_by.return_value.first.side_effect = [user_instance, None]
    from unittest.mock import patch
    with patch("app.api.auth_routes.verify_password", return_value=True):
        response = client.post("/login", json={
            "email": "testuser@example.com",
            "password": "testpass123"
        })
    assert response.status_code == 200
    assert "access_token" in response.json()

@patch("app.api.auth_routes.User")
def test_forgot_password(mock_user_model, mock_db_session):
    user_instance = MagicMock(**mock_user)
    user_instance.id_usuario = 1
    user_instance.nombre = "Test"
    user_instance.apellido = "User"
    user_instance.correo = "testuser@example.com"
    user_instance.proveedor = "email"
    user_instance.TFA_enabled = False
    mock_db_session.query.return_value.filter_by.return_value.first.return_value = user_instance
    with patch("app.api.auth_routes.fastmail.send_message", return_value=None):
        with patch("app.services.auth_service.create_access_token", return_value="token123"):
            response = client.post("/forgot-password", json={
                "email": "testuser@example.com"
            })
    assert response.status_code == 200
    assert response.json()["status"] == "success"

def test_update_user(mock_db_session):
    # Simula usuario existente
    user_instance = MagicMock(**mock_user)
    user_instance.id_usuario = 1
    user_instance.nombre = "Test"
    user_instance.apellido = "User"
    user_instance.correo = "testuser@example.com"
    user_instance.proveedor = "email"
    user_instance.TFA_enabled = False
    # Mock para búsqueda de usuario
    mock_db_session.query.return_value.filter.return_value.first.return_value = user_instance
    # Mock token JWT
    token = "fake.jwt.token"
    with patch("app.api.auth_routes.decode_access_token", return_value={"correo": "testuser@example.com"}):
        headers = {"Authorization": f"Bearer {token}"}
        response = client.put("/update-user", json={"name": "NuevoNombre"}, headers=headers)
    assert response.status_code == 200
    assert response.json()["status"] == "success"

def test_delete_user(mock_db_session):
    # Simula usuario existente
    user_instance = MagicMock(**mock_user)
    user_instance.id_usuario = 1
    user_instance.nombre = "Test"
    user_instance.apellido = "User"
    user_instance.correo = "testuser@example.com"
    user_instance.proveedor = "email"
    user_instance.TFA_enabled = False
    # Mock para búsqueda de usuario
    mock_db_session.query.return_value.filter_by.return_value.first.return_value = user_instance
    # Mock token JWT con rol admin
    token = "fake.jwt.token"
    with patch("app.api.auth_routes.decode_access_token", return_value={"correo": "testuser@example.com", "role": "admin"}):
        headers = {"Authorization": f"Bearer {token}"}
        response = client.delete(f"/delete-user/{user_instance.correo}", headers=headers)
    assert response.status_code == 200
    assert response.json()["status"] == "success"
