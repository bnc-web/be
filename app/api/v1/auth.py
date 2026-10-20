import hmac
from urllib.parse import urlencode, urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.dependencies import access_token_user, bearer, current_user, user_has_permission
from app.config.settings import get_settings
from app.constants.permissions import SETTINGS_EDIT
from app.db.session import get_db
from app.handlers.auth import AuthHandler
from app.models.enums import UserStatus
from app.models.identity import Permission, Role, RolePermission, User
from app.schemas.auth import (
    AuthTokenOutput,
    ChangePasswordInput,
    CurrentUserOutput,
    ForgotPasswordInput,
    LoginInput,
    MobileAdminSessionExchangeInput,
    MobileAdminSessionInput,
    MobileAdminSessionTicketOutput,
    MobileExchangeInput,
    OAuthSessionInput,
    RecoverPasswordInput,
    SetPasswordInput,
)
from app.services.admin_session_handoff_service import AdminSessionHandoffService
from app.services.auth_service import AuthProviderError

router = APIRouter(prefix="/auth", tags=["auth"])
handler = AuthHandler()
admin_session_handoffs = AdminSessionHandoffService()


def set_refresh_cookie(response: Response, refresh_token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        key=settings.auth_refresh_cookie_name,
        value=refresh_token,
        max_age=settings.auth_refresh_cookie_max_age,
        httponly=True,
        secure=settings.auth_cookie_secure,
        samesite=settings.auth_cookie_samesite,
        path="/api/v1/auth",
    )


def token_output(session) -> AuthTokenOutput:
    return AuthTokenOutput(
        access_token=session.access_token,
        expires_in=session.expires_in,
        password_setup_required=session.password_setup_required,
    )


def require_admin(db: Session, user: User) -> None:
    role_code = db.scalar(select(Role.code).where(Role.id == user.role_id))
    if role_code != "ADMIN" or not user_has_permission(db, user, SETTINGS_EDIT):
        raise HTTPException(status_code=403, detail="Admin access required")


@router.post("/login", response_model=AuthTokenOutput)
def login(payload: LoginInput, response: Response, db: Session = Depends(get_db)):
    session = handler.login(db, payload)
    set_refresh_cookie(response, session.refresh_token)
    return token_output(session)


@router.post("/forgot-password", status_code=204)
def forgot_password(payload: ForgotPasswordInput, db: Session = Depends(get_db)):
    handler.request_password_reset(db, payload)


@router.post("/password/recover", status_code=204)
def recover_password(payload: RecoverPasswordInput, db: Session = Depends(get_db)):
    handler.recover_password(db, payload)


@router.post(
    "/refresh",
    response_model=AuthTokenOutput,
    responses={204: {"description": "No active session"}},
)
def refresh(
    request: Request, response: Response, db: Session = Depends(get_db)
) -> AuthTokenOutput | Response:
    settings = get_settings()
    refresh_token = request.cookies.get(settings.auth_refresh_cookie_name)
    if not refresh_token:
        return Response(status_code=204)
    try:
        session = handler.refresh(db, refresh_token)
    except HTTPException as exc:
        if exc.status_code != 401:
            raise
        empty = Response(status_code=204)
        empty.delete_cookie(
            key=settings.auth_refresh_cookie_name,
            path="/api/v1/auth",
        )
        return empty
    set_refresh_cookie(response, session.refresh_token)
    return token_output(session)


@router.post("/oauth/session", response_model=AuthTokenOutput)
def oauth_session(
    payload: OAuthSessionInput, response: Response, db: Session = Depends(get_db)
):
    session = handler.accept_oauth_session(db, payload)
    set_refresh_cookie(response, session.refresh_token)
    return token_output(session)


@router.get("/mobile/google")
def mobile_google(code_challenge: str = Query(min_length=43, max_length=43, pattern=r"^[A-Za-z0-9_-]+$")):
    settings = get_settings()
    if settings.auth_provider != "supabase":
        raise HTTPException(status_code=503, detail="Native Google sign-in is not configured")
    target = settings.frontend_url.rstrip("/") + "/auth/android/callback"
    url = handler.auth.google_authorize_url(target)
    return RedirectResponse(url + "&" + urlencode({"code_challenge": code_challenge, "code_challenge_method": "s256"}))


@router.post("/mobile/exchange", response_model=AuthTokenOutput)
def mobile_exchange(payload: MobileExchangeInput, response: Response, db: Session = Depends(get_db)):
    if get_settings().auth_provider != "supabase":
        raise HTTPException(status_code=503, detail="Native Google sign-in is not configured")
    try:
        provider_session = handler.auth.exchange_pkce(payload.auth_code, payload.code_verifier)
    except AuthProviderError as exc:
        raise HTTPException(status_code=401, detail="Google sign-in expired or was cancelled. Try again.") from exc
    # Existing approval, status and membership checks remain authoritative.
    session = handler.accept_oauth_session(db, OAuthSessionInput(
        access_token=provider_session.access_token,
        refresh_token=provider_session.refresh_token,
        expires_in=provider_session.expires_in,
    ))
    set_refresh_cookie(response, session.refresh_token)
    return token_output(session)


@router.post(
    "/mobile/admin-session",
    response_model=MobileAdminSessionTicketOutput,
)
def mobile_admin_session(
    payload: MobileAdminSessionInput,
    response: Response,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
) -> MobileAdminSessionTicketOutput:
    if get_settings().auth_provider != "supabase":
        raise HTTPException(status_code=503, detail="Android admin handoff requires Supabase Auth")
    require_admin(db, user)
    ticket, expires_at = admin_session_handoffs.issue(db, user.id)
    response.headers["Cache-Control"] = "no-store"
    return MobileAdminSessionTicketOutput(ticket=ticket, expires_at=expires_at)


@router.post("/mobile/admin-session/exchange", response_model=AuthTokenOutput)
def exchange_mobile_admin_session(
    payload: MobileAdminSessionExchangeInput,
    response: Response,
    db: Session = Depends(get_db),
) -> AuthTokenOutput:
    if get_settings().auth_provider != "supabase":
        raise HTTPException(status_code=503, detail="Android admin handoff requires Supabase Auth")
    user_id = admin_session_handoffs.consume(db, payload.ticket)
    if user_id is None:
        raise HTTPException(status_code=401, detail="Admin session ticket is invalid or expired")

    user = db.get(User, user_id)
    if not user or user.status != UserStatus.ACTIVE:
        raise HTTPException(status_code=403, detail="Admin account is unavailable")
    require_admin(db, user)

    try:
        provider_session = handler.auth.create_independent_session(user.email)
    except AuthProviderError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    session = handler.accept_oauth_session(
        db,
        OAuthSessionInput(
            access_token=provider_session.access_token,
            refresh_token=provider_session.refresh_token,
            expires_in=provider_session.expires_in,
        ),
    )
    web_user = access_token_user(session.access_token, db)
    if web_user.id != user_id:
        raise HTTPException(status_code=401, detail="Admin session ticket is invalid")
    require_admin(db, web_user)

    set_refresh_cookie(response, session.refresh_token)
    response.headers["Cache-Control"] = "no-store"
    return token_output(session)


@router.post("/password", status_code=204)
def set_password(
    payload: SetPasswordInput,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication required")
    handler.set_password(db, user, credentials.credentials, payload.password)


@router.post("/password/change", status_code=204)
def change_password(
    payload: ChangePasswordInput,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
) -> None:
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication required")
    handler.change_password(db, user, credentials.credentials, payload)


@router.get("/google")
def google(return_to: str | None = None):
    settings = get_settings()
    target = return_to or settings.frontend_url
    origin = f"{urlsplit(target).scheme}://{urlsplit(target).netloc}"
    if origin not in settings.cors_origins:
        raise HTTPException(status_code=400, detail="Invalid authentication return URL")
    if settings.auth_provider == "supabase":
        return RedirectResponse(handler.auth.google_authorize_url(target))
    try:
        url, state = handler.auth.begin_google(target)
    except AuthProviderError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    response = RedirectResponse(url)
    response.set_cookie("bnc_oauth_state", state, max_age=600, httponly=True,
        secure=settings.auth_cookie_secure, samesite="lax", path="/api/v1/auth/google")
    return response


@router.get("/google/callback")
def google_callback(request: Request, state: str = "", code: str = "", error: str = ""):
    settings = get_settings()
    cookie = request.cookies.get("bnc_oauth_state", "")
    if settings.auth_provider != "local" or not state or not cookie or not hmac.compare_digest(state, cookie):
        raise HTTPException(status_code=400, detail="Invalid Google sign-in state")
    try:
        if error or not code:
            raise AuthProviderError("Google sign-in was cancelled")
        session, target = handler.auth.finish_google(code, state)
        response = RedirectResponse(target, status_code=303)
        set_refresh_cookie(response, session.refresh_token)
    except AuthProviderError as exc:
        response = RedirectResponse(settings.frontend_url.rstrip("/") + "/?" +
            urlencode({"error_description": str(exc)}), status_code=303)
    response.delete_cookie("bnc_oauth_state", path="/api/v1/auth/google")
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@router.post("/logout", status_code=204)
def logout(
    response: Response,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
):
    if credentials:
        handler.auth.logout(credentials.credentials)
    settings = get_settings()
    response.delete_cookie(key=settings.auth_refresh_cookie_name, path="/api/v1/auth")


@router.get("/me", response_model=CurrentUserOutput)
def me(db: Session = Depends(get_db), user: User = Depends(current_user)) -> CurrentUserOutput:
    role_code = db.scalar(select(Role.code).where(Role.id == user.role_id)) or ""
    permissions = db.scalars(
        select(Permission.code)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .where(RolePermission.role_id == user.role_id, RolePermission.allowed.is_(True))
        .order_by(Permission.code)
    ).all()
    return CurrentUserOutput(
        id=str(user.id),
        display_name=user.display_name,
        email=user.email,
        mobile=user.mobile,
        status=user.status.value,
        role_code=role_code,
        permissions=list(permissions),
        profile_picture_url=(
            f"/api/v1/members/{user.id}/profile-picture"
            if user.profile_picture_file_id
            else None
        ),
    )
