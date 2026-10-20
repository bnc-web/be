from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator


class LoginInput(BaseModel):
    identifier: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=255)


class ForgotPasswordInput(BaseModel):
    email: str = Field(min_length=5, max_length=255)


class OAuthSessionInput(BaseModel):
    access_token: str = Field(min_length=1)
    refresh_token: str = Field(min_length=1)
    expires_in: int = Field(default=3600, ge=1)


class MobileExchangeInput(BaseModel):
    auth_code: str = Field(min_length=1, max_length=2048)
    code_verifier: str = Field(min_length=43, max_length=128, pattern=r"^[A-Za-z0-9._~-]+$")


class MobileAdminSessionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    refresh_token: str | None = Field(
        default=None,
        min_length=1,
        max_length=2048,
        description="Deprecated; accepted for older clients but never used or stored.",
    )


class MobileAdminSessionTicketOutput(BaseModel):
    ticket: str
    expires_at: datetime


class MobileAdminSessionExchangeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ticket: str = Field(min_length=43, max_length=43, pattern=r"^[A-Za-z0-9_-]+$")


class AuthTokenOutput(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    password_setup_required: bool = False


class SetPasswordInput(BaseModel):
    password: str = Field(min_length=8, max_length=255)
    confirm_password: str = Field(min_length=8, max_length=255)

    @model_validator(mode="after")
    def passwords_match(self):
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match")
        return self


class RecoverPasswordInput(SetPasswordInput):
    token_hash: str = Field(min_length=20, max_length=2048)


class ChangePasswordInput(BaseModel):
    current_password: str = Field(min_length=1, max_length=255)
    new_password: str = Field(min_length=8, max_length=255)
    confirm_password: str = Field(min_length=8, max_length=255)

    @model_validator(mode="after")
    def passwords_match(self):
        if self.new_password != self.confirm_password:
            raise ValueError("Passwords do not match")
        if self.current_password == self.new_password:
            raise ValueError("New password must be different from the current password")
        return self


class CurrentUserOutput(BaseModel):
    id: str
    display_name: str
    email: str
    mobile: str | None
    status: str
    role_code: str
    permissions: list[str]
    profile_picture_url: str | None = None
