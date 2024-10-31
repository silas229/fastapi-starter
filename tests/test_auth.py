from datetime import timedelta
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from app.auth.auth_handlers import create_access_token
from app.config import Settings
from app.models import User


def test_register_user(client: TestClient, session: Session):
    response = client.post(
        "/auth/register", json={"email": "test@example.com", "password": "ValidPass123!"})
    user = session.get(User, 1)
    assert user is not None
    assert user.email == "test@example.com"
    assert response.status_code == 201
    assert "email" in response.json()
    assert response.json()["email"] == "test@example.com"


def test_register_user_already_exists(client: TestClient):
    client.post(
        "/auth/register", json={"email": "test@example.com", "password": "ValidPass123!"})
    response = client.post(
        "/auth/register", json={"email": "test@example.com", "password": "ValidPass123!"})
    assert response.status_code == 400
    assert response.json()["detail"] == "Email already registered"


def test_get_access_token(client: TestClient):
    client.post(
        "/auth/register", json={"email": "test@example.com", "password": "ValidPass123!"})
    response = client.post(
        "/auth/token", data={"username": "test@example.com", "password": "ValidPass123!"})
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["token_type"] == "bearer"


def test_register_account_disabled(client: TestClient):
    client.post(
        "/auth/register", json={"email": "test@example.com", "password": "ValidPass123!"})
    token_response = client.post(
        "/auth/token", data={"username": "test@example.com", "password": "ValidPass123!"})
    token = token_response.json()["access_token"]
    response = client.delete(
        "/auth/me", headers={"Authorization": f"Bearer {token}"})
    response = client.post(
        "/auth/register", json={"email": "test@example.com", "password": "ValidPass123!"})
    assert response.status_code == 400
    assert response.json()["detail"] == "Account disabled"


def test_get_access_token_wrong_password(client: TestClient):
    client.post(
        "/auth/register", json={"email": "test@example.com", "password": "ValidPass123!"})
    response = client.post(
        "/auth/token", data={"username": "test@example.com", "password": "InvalidPass123!"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect email or password"


def test_get_access_token_user_does_not_exist(client: TestClient):
    response = client.post(
        "/auth/token", data={"username": "test@example.com", "password": "ValidPass123!"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect email or password"


def test_get_current_user_info(token: str, client: TestClient):
    response = client.get(
        "/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["email"] == "test@example.com"


def test_invalid_token(client: TestClient):
    token = "invalidtoken"
    response = client.get(
        "/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"


def test_expired_token(client: TestClient, user: User, settings: Settings):
    token = create_access_token(
        {"sub": user.id}, settings, expires_delta=timedelta(seconds=-1))
    response = client.get(
        "/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"


def test_change_password(token: str, client: TestClient):
    response = client.patch("/auth/me/password", json={"password": "ValidPass123!",
                            "new_password": "newValidPass123!"}, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200


def test_change_password_incorrect(token: str, client: TestClient):
    response = client.patch("/auth/me/password", json={"password": "InvalidPass123!",
                            "new_password": "newValidPass123!"}, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 400


def test_change_email(token: str, client: TestClient):
    response = client.patch(
        "/auth/me/email", json={"email": "newtest@example.com"}, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["email"] == "newtest@example.com"


def test_delete_user(token: str, client: TestClient, session: Session):
    response = client.delete(
        "/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["email"] == "test@example.com"
    assert session.exec(select(User).where(
        User.deleted_at == None)).first() is None


def test_get_current_user_info_from_deleted_user(token: str, client: TestClient):
    client.delete(
        "/auth/me", headers={"Authorization": f"Bearer {token}"})
    response = client.get(
        "/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"
