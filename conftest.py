import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel, Session, StaticPool, create_engine

from app.database import get_session
from app.dependencies import get_settings
from app.main import app
from app.models import User


@pytest.fixture(name="session")
def session_fixture():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


@pytest.fixture(name="client")
def client_fixture(session: Session):
    def get_session_override():
        return session

    app.dependency_overrides[get_session] = get_session_override

    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


@pytest.fixture(name="token")
def token_fixture(client: TestClient):
    client.post(
        "/auth/register", json={"email": "test@example.com", "password": "ValidPass123!"})
    token_response = client.post(
        "/auth/token", data={"username": "test@example.com", "password": "ValidPass123!"})
    yield token_response.json()["access_token"]


@pytest.fixture(name="settings")
def settings_fixture():
    return get_settings()


@pytest.fixture(name="user")
def user_fixture(session: Session):
    user = User(email="test@example.com", password="ValidPass123!")
    session.add(user)
    session.commit()
    session.refresh(user)
    yield user
