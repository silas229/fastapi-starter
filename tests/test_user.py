import pytest
from pydantic import SecretStr, ValidationError
from app.schemas import UserChangePassword, UserCreate


def test_user_create_valid():
    from pydantic import SecretStr
    user = UserCreate(email="test@example.com",
                      password=SecretStr("ValidPass123!"))
    assert user.email == "test@example.com"
    assert user.password.get_secret_value() == "ValidPass123!"


def test_user_create_invalid_email():
    with pytest.raises(ValidationError):
        UserCreate(email="invalid-email", password=SecretStr("ValidPass123!"))


def test_user_create_short_password():
    with pytest.raises(ValidationError):
        UserCreate(email="test@example.com", password=SecretStr("Short1!"))


def test_user_create_no_uppercase():
    with pytest.raises(ValidationError):
        UserCreate(email="test@example.com",
                   password=SecretStr("nouppercase1!"))


def test_user_create_no_lowercase():
    with pytest.raises(ValidationError):
        UserCreate(email="test@example.com",
                   password=SecretStr("NOLOWERCASE1!"))


def test_user_create_no_digit():
    with pytest.raises(ValidationError):
        UserCreate(email="test@example.com",
                   password=SecretStr("NoDigitPass!"))


def test_user_create_no_special_char():
    with pytest.raises(ValidationError):
        UserCreate(email="test@example.com",
                   password=SecretStr("NoSpecialChar1"))


def test_user_change_password_new_password_too_short():
    with pytest.raises(ValidationError) as exc_info:
        UserChangePassword(password=SecretStr("ValidPass123!"),
                           new_password=SecretStr("Short1!"))
    assert "Password must be at least 8 characters long" in str(
        exc_info.value)


def test_user_change_password_same_password():
    with pytest.raises(ValidationError) as exc_info:
        UserChangePassword(password=SecretStr("ValidPass123!"),
                           new_password=SecretStr("ValidPass123!"))
    assert "New password must be different from the current password" in str(
        exc_info.value)
