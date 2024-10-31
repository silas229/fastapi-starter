from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session
from app import schemas
from app.auth.hashing import verify_password
from app.config import Settings
from app.database import get_session
from app.auth.auth_handlers import authenticate_user, create_access_token, get_current_user
from app.dependencies import get_settings
from app.models import User
from app.services import user as userservice

router = APIRouter()


@router.post("/register", response_model=schemas.UserRead, status_code=201)
def register_user(user: schemas.UserCreate, session: Session = Depends(get_session)):
    db_user = userservice.get_user_by_email(
        session, user.email, include_deleted=True)
    if db_user:
        if db_user.deleted_at:
            raise HTTPException(status_code=400, detail="Account disabled")
        else:
            raise HTTPException(
                status_code=400, detail="Email already registered")

    new_user = userservice.create_user(
        session, user.email, user.password.get_secret_value())
    return new_user


@router.post("/token")
async def get_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    settings: Settings = Depends(get_settings),
    session: Session = Depends(get_session),
) -> schemas.Token:
    user = authenticate_user(session, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(
        data={"sub": user.id}, settings=settings
    )
    return schemas.Token(access_token=access_token, token_type="bearer")


@router.get("/me", response_model=schemas.UserRead)
def get_current_user_info(current_user: schemas.UserRead = Depends(get_current_user)):
    return current_user


@router.patch("/me/password", response_model=schemas.UserRead)
def change_password(
    data: schemas.UserChangePassword,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    if not verify_password(data.password.get_secret_value(), current_user.password):
        raise HTTPException(status_code=400, detail="Incorrect password")
    userservice.change_password(
        session, current_user, data.new_password.get_secret_value())
    return current_user


@router.patch("/me/email", response_model=schemas.UserRead)
def change_email(
    data: schemas.UserChangeEmail,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    userservice.change_email(session, current_user, data.email)
    return current_user


@router.delete("/me", response_model=schemas.UserRead)
def delete_user(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    userservice.delete_user(session, current_user)
    return current_user
