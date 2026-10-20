from dataclasses import dataclass
from urllib.parse import urlencode

import httpx

from app.config.settings import Settings, get_settings
from app.services.supabase_admin_service import SupabaseAdminError, SupabaseAdminService


class AuthProviderError(Exception):
    pass


@dataclass(frozen=True)
class AuthSession:
    access_token: str
    refresh_token: str
    expires_in: int
    password_setup_required: bool = False


class SupabaseAuthService:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def login(self, identifier: str, password: str) -> AuthSession:
        credential = "email" if "@" in identifier else "phone"
        return self._token({credential: identifier.strip(), "password": password})

    def refresh(self, refresh_token: str) -> AuthSession:
        return self._token({"refresh_token": refresh_token}, grant_type="refresh_token")

    def exchange_pkce(self, auth_code: str, code_verifier: str) -> AuthSession:
        return self._token({"auth_code": auth_code, "code_verifier": code_verifier}, grant_type="pkce")

    def logout(self, access_token: str) -> None:
        api_key = self.settings.supabase_public_api_key
        if not api_key:
            return
        try:
            httpx.post(
                f"{self.settings.supabase_url.rstrip('/')}/auth/v1/logout",
                params={"scope": "local"},
                headers={
                    "apikey": api_key,
                    "Authorization": f"Bearer {access_token}",
                },
                timeout=10,
            )
        except httpx.HTTPError:
            # Local logout must still succeed when the provider is temporarily unavailable.
            return

    def update_password(self, access_token: str, password: str) -> None:
        api_key = self.settings.supabase_public_api_key
        if not api_key:
            raise AuthProviderError("Supabase authentication is not configured")
        try:
            response = httpx.put(
                f"{self.settings.supabase_url.rstrip('/')}/auth/v1/user",
                headers={
                    "apikey": api_key,
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                },
                json={"password": password},
                timeout=10,
            )
        except httpx.HTTPError as exc:
            raise AuthProviderError("Authentication service is unavailable") from exc
        if not response.is_success:
            raise AuthProviderError(
                self._error_message(response, "Password could not be updated")
            )

    def request_password_reset(self, email: str, redirect_to: str) -> None:
        api_key = self.settings.supabase_public_api_key
        if not api_key:
            raise AuthProviderError("Supabase authentication is not configured")
        try:
            response = httpx.post(
                f"{self.settings.supabase_url.rstrip('/')}/auth/v1/recover",
                params={"redirect_to": redirect_to},
                headers={"apikey": api_key, "Content-Type": "application/json"},
                json={"email": email.strip().lower()},
                timeout=10,
            )
        except httpx.HTTPError as exc:
            raise AuthProviderError("Authentication service is unavailable") from exc
        if not response.is_success:
            raise AuthProviderError(
                self._error_message(response, "Password reset could not be requested")
            )

    def verify_recovery_token(self, token_hash: str) -> AuthSession:
        api_key = self.settings.supabase_public_api_key
        if not api_key:
            raise AuthProviderError("Supabase authentication is not configured")
        try:
            response = httpx.post(
                f"{self.settings.supabase_url.rstrip('/')}/auth/v1/verify",
                headers={"apikey": api_key, "Content-Type": "application/json"},
                json={"token_hash": token_hash, "type": "recovery"},
                timeout=10,
            )
        except httpx.HTTPError as exc:
            raise AuthProviderError("Authentication service is unavailable") from exc
        if not response.is_success:
            raise AuthProviderError(
                self._error_message(response, "Password reset link is invalid or expired")
            )
        try:
            data = response.json()
        except ValueError as exc:
            raise AuthProviderError("Authentication service returned an invalid response") from exc
        try:
            return AuthSession(
                access_token=data["access_token"],
                refresh_token=data["refresh_token"],
                expires_in=int(data.get("expires_in", 3600)),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthProviderError("Authentication service returned an invalid response") from exc

    def create_independent_session(self, email: str) -> AuthSession:
        if not self.settings.supabase_url or not self.settings.supabase_admin_api_key:
            raise AuthProviderError("Supabase Admin API is not configured")
        api_key = self.settings.supabase_public_api_key
        if not api_key:
            raise AuthProviderError("Supabase authentication is not configured")
        try:
            token_hash = SupabaseAdminService(self.settings).generate_magic_link_token(email)
        except SupabaseAdminError as exc:
            raise AuthProviderError("An independent browser session could not be created") from exc
        try:
            response = httpx.post(
                f"{self.settings.supabase_url.rstrip('/')}/auth/v1/verify",
                headers={"apikey": api_key, "Content-Type": "application/json"},
                json={"token_hash": token_hash, "type": "magiclink"},
                timeout=10,
            )
        except httpx.HTTPError as exc:
            raise AuthProviderError("Authentication service is unavailable") from exc
        if not response.is_success:
            raise AuthProviderError("An independent browser session could not be created")
        try:
            data = response.json()
        except ValueError as exc:
            raise AuthProviderError("Authentication service returned an invalid response") from exc
        try:
            return AuthSession(
                access_token=data["access_token"],
                refresh_token=data["refresh_token"],
                expires_in=int(data.get("expires_in", 3600)),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthProviderError("Authentication service returned an invalid response") from exc

    def google_authorize_url(self, return_to: str) -> str:
        query = urlencode({"provider": "google", "redirect_to": return_to})
        return f"{self.settings.supabase_url.rstrip('/')}/auth/v1/authorize?{query}"

    def _token(self, payload: dict[str, str], grant_type: str = "password") -> AuthSession:
        api_key = self.settings.supabase_public_api_key
        if not api_key:
            raise AuthProviderError("Supabase authentication is not configured")
        try:
            response = httpx.post(
                f"{self.settings.supabase_url.rstrip('/')}/auth/v1/token",
                params={"grant_type": grant_type},
                headers={
                    "apikey": api_key,
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=10,
            )
        except httpx.HTTPError as exc:
            print(f"Auth provider error: {exc}")
            raise AuthProviderError("Authentication service is unavailable") from exc
        if not response.is_success:
            raise AuthProviderError("Invalid login credentials")
        data = response.json()
        try:
            return AuthSession(
                access_token=data["access_token"],
                refresh_token=data["refresh_token"],
                expires_in=int(data.get("expires_in", 3600)),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthProviderError("Authentication service returned an invalid response") from exc

    @staticmethod
    def _error_message(response: httpx.Response, fallback: str) -> str:
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        if isinstance(payload, dict):
            message = payload.get("message") or payload.get("msg") or payload.get("error_description")
            if message:
                return str(message)
        return fallback


class AuthService:
    """Select a provider explicitly; retained Supabase support is for migration rollback."""

    def __new__(cls, settings: Settings | None = None):
        settings = settings or get_settings()
        if getattr(settings, "auth_provider", "supabase") == "supabase":
            return SupabaseAuthService(settings)
        from app.services.local_auth_service import LocalAuthService
        return LocalAuthService(settings)
