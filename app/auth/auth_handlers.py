from typing import Annotated
import jwt
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import Session

from app.config import Settings
from app.auth.hashing import verify_password
from app.models import User
from app.services.user import get_user_by_email, get_user_by_id
from app.database import get_session
from app.dependencies import get_settings
from app.schemas import TokenData


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")


def authenticate_user(session: Session, email: str, password: str):
    user = get_user_by_email(session, email)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user


def create_access_token(data: dict, settings: Settings, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if settings.SECRET_KEY == "":
        raise Exception("SECRET_KEY is not set")
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(
            timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Security(oauth2_scheme)], session: Session = Depends(get_session), settings: Settings = Depends(get_settings)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY,
                             algorithms=[settings.ALGORITHM])
        id: int = payload.get("sub")
        token_data = TokenData(id=id)
    except jwt.InvalidTokenError:
        raise credentials_exception
    if token_data.id is None:
        raise credentials_exception
    user = get_user_by_id(session, token_data.id)
    if user is None:
        raise credentials_exception
    return user
