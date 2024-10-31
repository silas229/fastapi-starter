import re
from pydantic import Secret, SecretStr
from app.config import settings


def get_settings():
    return settings


def validate_password(str: SecretStr) -> SecretStr:
    pw = str.get_secret_value()
    if len(pw) < 8:
        raise ValueError('Password must be at least 8 characters long')

    if not re.search(r'[A-Z]', pw):
        raise ValueError(
            'Password must contain at least one uppercase letter')

    if not re.search(r'[a-z]', pw):
        raise ValueError(
            'Password must contain at least one lowercase letter')

    if not re.search(r'[0-9]', pw):
        raise ValueError('Password must contain at least one digit')

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', pw):
        raise ValueError(
            'Password must contain at least one of the following characters: !@#$%^&*(),.?":{}|<>')

    return str
