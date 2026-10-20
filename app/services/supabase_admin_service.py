from dataclasses import dataclass
from uuid import UUID

import httpx

from app.config.settings import Settings, get_settings


class SupabaseAdminError(Exception):
    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        error_code: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code


@dataclass(frozen=True)
class CreatedAuthUser:
    id: UUID
    email: str


class SupabaseAdminService:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def create_user(self, email: str, password: str, display_name: str) -> CreatedAuthUser:
        response = self._request(
            "POST",
            "/auth/v1/admin/users",
            json={
                "email": email,
                "password": password,
                "email_confirm": True,
                "user_metadata": {"display_name": display_name},
            },
        )
        data = response.json()
        try:
            return CreatedAuthUser(id=UUID(data["id"]), email=data["email"])
        except (KeyError, TypeError, ValueError) as exc:
            raise SupabaseAdminError("Supabase returned an invalid user response") from exc

    def delete_user(self, auth_user_id: UUID) -> None:
        self._request("DELETE", f"/auth/v1/admin/users/{auth_user_id}")

    def invite_user(self, email: str, display_name: str, redirect_to: str) -> CreatedAuthUser:
        response = self._request(
            "POST",
            "/auth/v1/invite",
            params={"redirect_to": redirect_to},
            json={"email": email, "data": {"display_name": display_name}},
        )
        data = response.json()
        try:
            user = data.get("user", data)
            return CreatedAuthUser(id=UUID(user["id"]), email=user["email"])
        except (KeyError, TypeError, ValueError) as exc:
            raise SupabaseAdminError("Supabase returned an invalid invitation response") from exc

    def send_password_reset(self, email: str, redirect_to: str) -> None:
        self._request(
            "POST",
            "/auth/v1/recover",
            params={"redirect_to": redirect_to},
            json={"email": email},
        )

    def generate_magic_link_token(self, email: str) -> str:
        response = self._request(
            "POST",
            "/auth/v1/admin/generate_link",
            json={"type": "magiclink", "email": email},
        )
        try:
            token_hash = response.json()["hashed_token"]
        except (KeyError, TypeError, ValueError) as exc:
            raise SupabaseAdminError("Supabase returned an invalid magic-link response") from exc
        if not isinstance(token_hash, str) or not token_hash:
            raise SupabaseAdminError("Supabase returned an invalid magic-link response")
        return token_hash

    def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        key = self.settings.supabase_admin_api_key
        if not key:
            raise SupabaseAdminError("SUPABASE_SECRET_KEY is not configured")
        headers = {"apikey": key}
        if not key.startswith("sb_secret_"):
            headers["Authorization"] = f"Bearer {key}"
        try:
            response = httpx.request(
                method,
                f"{self.settings.supabase_url.rstrip('/')}{path}",
                headers=headers,
                timeout=15,
                **kwargs,
            )
        except httpx.HTTPError as exc:
            raise SupabaseAdminError("Supabase Admin API is unavailable") from exc
        if not response.is_success:
            detail, error_code = self._error_detail(response)
            raise SupabaseAdminError(
                detail,
                status_code=response.status_code,
                error_code=error_code,
            )
        return response

    @staticmethod
    def _error_detail(response: httpx.Response) -> tuple[str, str | None]:
        """Extract the useful, non-secret error fields returned by Supabase Auth."""
        try:
            payload = response.json()
        except ValueError:
            payload = {}

        if not isinstance(payload, dict):
            payload = {}
        message = payload.get("message") or payload.get("msg") or payload.get("error_description")
        error_code = payload.get("error_code") or payload.get("error")
        if message and error_code and str(error_code) not in str(message):
            message = f"{message} ({error_code})"
        if message:
            return str(message), str(error_code) if error_code else None
        if error_code:
            return str(error_code), str(error_code)
        return f"Supabase Admin API rejected the request ({response.status_code})", None
