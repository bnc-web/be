from types import SimpleNamespace

import httpx
import pytest

from app.services.auth_service import AuthProviderError, AuthService


def service() -> AuthService:
    settings = SimpleNamespace(
        supabase_url="https://example.supabase.co",
        supabase_public_api_key="public-key",
        supabase_admin_api_key="admin-key",
    )
    return AuthService(settings=settings)


def test_password_login_uses_supabase_token_endpoint(monkeypatch) -> None:
    def fake_post(url, **kwargs):
        assert url == "https://example.supabase.co/auth/v1/token"
        assert kwargs["params"] == {"grant_type": "password"}
        assert kwargs["json"] == {"email": "member@example.com", "password": "secret"}
        return httpx.Response(
            200,
            json={"access_token": "access", "refresh_token": "refresh", "expires_in": 3600},
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    session = service().login("member@example.com", "secret")
    assert session.access_token == "access"
    assert session.refresh_token == "refresh"


def test_invalid_credentials_are_not_leaked(monkeypatch) -> None:
    monkeypatch.setattr(httpx, "post", lambda *args, **kwargs: httpx.Response(400))
    with pytest.raises(AuthProviderError, match="Invalid login credentials"):
        service().login("member@example.com", "wrong")


def test_update_password_uses_authenticated_user_endpoint(monkeypatch) -> None:
    def fake_put(url, **kwargs):
        assert url == "https://example.supabase.co/auth/v1/user"
        assert kwargs["headers"] == {
            "apikey": "public-key",
            "Authorization": "Bearer access-token",
            "Content-Type": "application/json",
        }
        assert kwargs["json"] == {"password": "new-password"}
        return httpx.Response(200, json={"user": {"id": "user-id"}})

    monkeypatch.setattr(httpx, "put", fake_put)
    service().update_password("access-token", "new-password")


def test_update_password_surfaces_provider_message(monkeypatch) -> None:
    monkeypatch.setattr(
        httpx,
        "put",
        lambda *args, **kwargs: httpx.Response(422, json={"msg": "Password is too weak"}),
    )
    with pytest.raises(AuthProviderError, match="Password is too weak"):
        service().update_password("access-token", "weak")


def test_admin_magic_link_creates_independent_web_session(monkeypatch) -> None:
    requests = []

    def admin_request(method, url, **kwargs):
        requests.append((method, url, kwargs))
        assert method == "POST"
        assert url == "https://example.supabase.co/auth/v1/admin/generate_link"
        assert kwargs["headers"]["apikey"] == "admin-key"
        assert kwargs["json"] == {
            "type": "magiclink",
            "email": "admin@example.com",
        }
        return httpx.Response(200, json={"hashed_token": "one-time-hash"})

    def verify_post(url, **kwargs):
        assert url == "https://example.supabase.co/auth/v1/verify"
        assert kwargs["headers"]["apikey"] == "public-key"
        assert kwargs["json"] == {
            "token_hash": "one-time-hash",
            "type": "magiclink",
        }
        return httpx.Response(
            200,
            json={
                "access_token": "browser-access",
                "refresh_token": "browser-refresh",
                "expires_in": 3600,
            },
        )

    monkeypatch.setattr(httpx, "request", admin_request)
    monkeypatch.setattr(httpx, "post", verify_post)

    session = service().create_independent_session("admin@example.com")

    assert len(requests) == 1
    assert session.access_token == "browser-access"
    assert session.refresh_token == "browser-refresh"


def test_logout_revokes_only_current_supabase_session(monkeypatch) -> None:
    def post(url, **kwargs):
        assert url == "https://example.supabase.co/auth/v1/logout"
        assert kwargs["params"] == {"scope": "local"}
        return httpx.Response(204)

    monkeypatch.setattr(httpx, "post", post)
    service().logout("browser-access")
