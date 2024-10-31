from pydantic import AfterValidator, BaseModel, ConfigDict, EmailStr, Field, SecretStr, model_validator
from typing import Annotated, Optional
from datetime import datetime

from app.dependencies import get_settings, validate_password


Password = Annotated[SecretStr, Field(
    description="Password"), AfterValidator(validate_password)]


class UserCreate(BaseModel):
    email: EmailStr
    password: Password


class UserRead(BaseModel):
    id: int
    email: EmailStr
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserLogin(BaseModel):
    email: EmailStr
    password: Password


class UserChangePassword(BaseModel):
    password: Password = Field(description="Current password")
    new_password: Password = Field(description="New password")

    @model_validator(mode="after")
    def check_passwords_match(self):
        if self.password.get_secret_value() == self.new_password.get_secret_value():
            raise ValueError(
                "New password must be different from the current password")
        return self


class UserChangeEmail(BaseModel):
    email: EmailStr


class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int = Field(description="Token expiration time in seconds",
                            default=get_settings().ACCESS_TOKEN_EXPIRE_MINUTES * 60)


class TokenData(BaseModel):
    id: int | None = None
