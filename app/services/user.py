from datetime import datetime
from typing import Optional
from sqlmodel import Session, select
from app.models import User
from app.auth.hashing import hash_password


def get_user_by_email(session: Session, email: str, include_deleted=False) -> Optional[User]:
    statement = select(User).where(
        User.email == email)
    if not include_deleted:
        statement = statement.where(User.deleted_at == None)
    return session.exec(statement).first()


def get_user_by_id(session: Session, id: int, include_deleted=False) -> Optional[User]:
    statement = select(User).where(
        User.id == id)
    if not include_deleted:
        statement = statement.where(User.deleted_at == None)
    return session.exec(statement).first()


def create_user(session: Session, email: str, password: str) -> User:
    hashed_password = hash_password(password)
    user = User(email=email, password=hashed_password)
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def change_password(session: Session, user: User, new_password: str) -> User:
    user.password = hash_password(new_password)
    user.updated_at = datetime.now()
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def change_email(session: Session, user: User, new_email: str) -> User:
    user.email = new_email
    user.updated_at = datetime.now()
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def delete_user(session: Session, user: User) -> User:
    user.deleted_at = datetime.now()
    user.updated_at = datetime.now()
    session.add(user)
    session.commit()
    session.refresh(user)
    return user
