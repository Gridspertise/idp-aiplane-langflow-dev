from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from lfx.log.logger import logger
from pydantic import BaseModel
from sqlmodel import select

from langflow.api.utils import DbSession
from langflow.api.v1.schemas import Token
from langflow.api.v1.sso import _OIDC_FEDERATED_SESSION_COOKIE, set_federated_session_cookie
from langflow.initial_setup.setup import get_or_create_default_folder
from langflow.services.auth.exceptions import AuthenticationError
from langflow.services.auth.oidc import (
    OIDCAuthenticationError,
    decrypt_federated_session,
    end_session_url,
    resolve_provider_metadata,
)
from langflow.services.database.models.auth.sso import SSOConfig
from langflow.services.database.models.user.crud import get_user_by_id
from langflow.services.database.models.user.model import UserRead
from langflow.services.deps import get_auth_service, get_settings_service, get_variable_service
from langflow.services.rate_limit import check_rate_limit

router = APIRouter(tags=["Login"])


def get_limiter_from_app(request: Request):
    """Get the rate limiter from app state (initialized after settings load)."""
    return request.app.state.limiter


class SessionResponse(BaseModel):
    """Session validation response."""

    authenticated: bool
    user: UserRead | None = None
    store_api_key: str | None = None


class LogoutResponse(BaseModel):
    """A completed local logout and an optional browser redirect to the IdP."""

    message: str
    logout_url: str | None = None


def _is_configured_emergency_username(username: str) -> bool:
    """Return whether an account is explicitly designated for emergency login."""
    auth_settings = get_settings_service().auth_settings
    if not auth_settings.SSO_ENABLED:
        return True
    allowed = {
        configured.casefold()
        for configured in auth_settings.SSO_EMERGENCY_USERNAMES.split(",")
        if configured.strip()
    }
    return username.casefold() in allowed


@router.post("/login", response_model=Token, include_in_schema=False)
async def login_to_get_access_token(
    request: Request,
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: DbSession,
):
    """Login endpoint with rate limiting applied via app.state.limiter."""
    # Check rate limit (limiter is initialized in main.py after settings load)
    check_rate_limit(request)
    if not _is_configured_emergency_username(form_data.username):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    auth_settings = get_settings_service().auth_settings
    try:
        auth = get_auth_service()
        user = await auth.authenticate_user(form_data.username, form_data.password, db, request)
    except Exception as exc:
        if isinstance(exc, HTTPException):
            raise
        # Log the actual error server-side but don't expose it to clients
        from loguru import logger

        logger.error(f"Authentication error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during authentication",
        ) from exc

    if user:
        if auth_settings.SSO_ENABLED and not user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        tokens = await auth.create_user_tokens(user_id=user.id, db=db, update_last_login=True)
        response.set_cookie(
            "refresh_token_lf",
            tokens["refresh_token"],
            httponly=auth_settings.REFRESH_HTTPONLY,
            samesite=auth_settings.REFRESH_SAME_SITE,
            secure=auth_settings.REFRESH_SECURE,
            expires=auth_settings.REFRESH_TOKEN_EXPIRE_SECONDS,
            domain=auth_settings.COOKIE_DOMAIN,
        )
        response.set_cookie(
            "access_token_lf",
            tokens["access_token"],
            httponly=auth_settings.ACCESS_HTTPONLY,
            samesite=auth_settings.ACCESS_SAME_SITE,
            secure=auth_settings.ACCESS_SECURE,
            expires=auth_settings.ACCESS_TOKEN_EXPIRE_SECONDS,
            domain=auth_settings.COOKIE_DOMAIN,
        )
        response.set_cookie(
            "apikey_tkn_lflw",
            str(user.store_api_key),
            httponly=auth_settings.ACCESS_HTTPONLY,
            samesite=auth_settings.ACCESS_SAME_SITE,
            secure=auth_settings.ACCESS_SECURE,
            expires=None,  # Set to None to make it a session cookie
            domain=auth_settings.COOKIE_DOMAIN,
        )
        await get_variable_service().initialize_user_variables(user.id, db)
        # Initialize agentic variables if agentic experience is enabled
        from langflow.api.utils.mcp.agentic_mcp import initialize_agentic_user_variables

        # Create default project for user if it doesn't exist
        _ = await get_or_create_default_folder(db, user.id)

        if get_settings_service().settings.agentic_experience:
            await initialize_agentic_user_variables(user.id, db)

        return tokens
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Bearer"},
    )


@router.get("/auto_login", include_in_schema=False)
async def auto_login(response: Response, db: DbSession):
    auth_settings = get_settings_service().auth_settings

    if auth_settings.AUTO_LOGIN:
        auth = get_auth_service()
        user_id, tokens = await auth.create_user_longterm_token(db)
        # The auto-login token is now short-lived, so set the refresh
        # cookie too — the client refreshes it transparently via /refresh instead
        # of relying on a year-long token.
        if tokens.get("refresh_token"):
            response.set_cookie(
                "refresh_token_lf",
                tokens["refresh_token"],
                httponly=auth_settings.REFRESH_HTTPONLY,
                samesite=auth_settings.REFRESH_SAME_SITE,
                secure=auth_settings.REFRESH_SECURE,
                expires=auth_settings.REFRESH_TOKEN_EXPIRE_SECONDS,
                domain=auth_settings.COOKIE_DOMAIN,
            )
        response.set_cookie(
            "access_token_lf",
            tokens["access_token"],
            httponly=auth_settings.ACCESS_HTTPONLY,
            samesite=auth_settings.ACCESS_SAME_SITE,
            secure=auth_settings.ACCESS_SECURE,
            expires=None,  # Set to None to make it a session cookie
            domain=auth_settings.COOKIE_DOMAIN,
        )

        user = await get_user_by_id(db, user_id)

        if user:
            if user.store_api_key is None:
                user.store_api_key = ""

            response.set_cookie(
                "apikey_tkn_lflw",
                str(user.store_api_key),  # Ensure it's a string
                httponly=auth_settings.ACCESS_HTTPONLY,
                samesite=auth_settings.ACCESS_SAME_SITE,
                secure=auth_settings.ACCESS_SECURE,
                expires=None,  # Set to None to make it a session cookie
                domain=auth_settings.COOKIE_DOMAIN,
            )

            if get_settings_service().settings.agentic_experience:
                from langflow.api.utils.mcp.agentic_mcp import initialize_agentic_user_variables

                await initialize_agentic_user_variables(user.id, db)

        return tokens

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "message": "Auto login is disabled.",
            "auto_login": False,
        },
    )


@router.post("/refresh", include_in_schema=False)
async def refresh_token(
    request: Request,
    response: Response,
    db: DbSession,
):
    auth_settings = get_settings_service().auth_settings

    token = request.cookies.get("refresh_token_lf")

    if token:
        auth = get_auth_service()
        tokens = await auth.create_refresh_token(token, db)
        encrypted_session = request.cookies.get(_OIDC_FEDERATED_SESSION_COOKIE)
        if encrypted_session:
            try:
                federated_session = decrypt_federated_session(
                    encrypted_session,
                    get_settings_service(),
                    max_age_seconds=auth_settings.REFRESH_TOKEN_EXPIRE_SECONDS,
                )
                set_federated_session_cookie(response, federated_session.provider_slug)
            except OIDCAuthenticationError:
                await logger.adebug("OIDC federated session cookie was invalid during refresh")
        response.set_cookie(
            "refresh_token_lf",
            tokens["refresh_token"],
            httponly=auth_settings.REFRESH_HTTPONLY,
            samesite=auth_settings.REFRESH_SAME_SITE,
            secure=auth_settings.REFRESH_SECURE,
            expires=auth_settings.REFRESH_TOKEN_EXPIRE_SECONDS,
            domain=auth_settings.COOKIE_DOMAIN,
        )
        response.set_cookie(
            "access_token_lf",
            tokens["access_token"],
            httponly=auth_settings.ACCESS_HTTPONLY,
            samesite=auth_settings.ACCESS_SAME_SITE,
            secure=auth_settings.ACCESS_SECURE,
            expires=auth_settings.ACCESS_TOKEN_EXPIRE_SECONDS,
            domain=auth_settings.COOKIE_DOMAIN,
        )
        return tokens
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )


@router.get("/session", include_in_schema=False)
async def get_session(
    request: Request,
    db: DbSession,
) -> SessionResponse:
    """Validate session and return user information.

    This endpoint checks if the user is authenticated via cookie or Authorization header.
    It does not raise an error if unauthenticated, allowing the frontend to gracefully
    handle the session state.
    """
    from langflow.services.auth.utils import _get_external_token, oauth2_login

    # Try to get the token from the request (cookie or Authorization header)
    try:
        token = await oauth2_login(request)
        # Extract the external credential separately so a present-but-invalid
        # native cookie can't shadow a valid external one (mirrors get_current_user
        # and the WS/SSE paths). oauth2_login may already have collapsed to the
        # external credential, in which case the service's dedup guard makes the
        # fallback a no-op.
        external_token = _get_external_token(request.headers, request.cookies)
        if not token and not external_token:
            return SessionResponse(authenticated=False)

        # Validate the token and get user
        user = await get_auth_service().get_current_user_from_access_token(token, db, external_token=external_token)
        if not user or not user.is_active:
            return SessionResponse(authenticated=False)

        return SessionResponse(
            authenticated=True,
            user=UserRead.model_validate(user, from_attributes=True),
        )
    except (AuthenticationError, HTTPException, ValueError) as _:
        # Any authentication error means not authenticated
        return SessionResponse(authenticated=False)


@router.post("/logout", response_model=LogoutResponse, include_in_schema=False)
async def logout(request: Request, response: Response, db: DbSession) -> LogoutResponse:
    """Clear Langflow cookies and return a safe Keycloak logout redirect when applicable."""
    auth_settings = get_settings_service().auth_settings
    logout_url = None
    encrypted_session = request.cookies.get(_OIDC_FEDERATED_SESSION_COOKIE)
    if encrypted_session:
        try:
            federated_session = decrypt_federated_session(
                encrypted_session,
                get_settings_service(),
                max_age_seconds=auth_settings.REFRESH_TOKEN_EXPIRE_SECONDS,
            )
            config = (
                await db.exec(
                    select(SSOConfig).where(
                        SSOConfig.slug == federated_session.provider_slug,
                        SSOConfig.enabled == True,  # noqa: E712
                        SSOConfig.protocol == "oidc",
                    )
                )
            ).first()
            if config is not None:
                logout_url = end_session_url(config, await resolve_provider_metadata(config))
        except OIDCAuthenticationError:
            await logger.awarning("OIDC federated logout could not be prepared")


    response.delete_cookie(
        "refresh_token_lf",
        httponly=auth_settings.REFRESH_HTTPONLY,
        samesite=auth_settings.REFRESH_SAME_SITE,
        secure=auth_settings.REFRESH_SECURE,
        domain=auth_settings.COOKIE_DOMAIN,
    )
    response.delete_cookie(
        "access_token_lf",
        httponly=auth_settings.ACCESS_HTTPONLY,
        samesite=auth_settings.ACCESS_SAME_SITE,
        secure=auth_settings.ACCESS_SECURE,
        domain=auth_settings.COOKIE_DOMAIN,
    )
    response.delete_cookie(
        "apikey_tkn_lflw",
        httponly=auth_settings.ACCESS_HTTPONLY,
        samesite=auth_settings.ACCESS_SAME_SITE,
        secure=auth_settings.ACCESS_SECURE,
        domain=auth_settings.COOKIE_DOMAIN,
    )
    response.delete_cookie(
        _OIDC_FEDERATED_SESSION_COOKIE,
        httponly=True,
        samesite="lax",
        secure=auth_settings.REFRESH_SECURE,
        domain=auth_settings.COOKIE_DOMAIN,
        path="/",
    )
    return LogoutResponse(message="Logout successful", logout_url=logout_url)
