"""Browser-facing OIDC routes backed by persisted SSO configurations."""

from __future__ import annotations

import secrets
import time
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from lfx.log.logger import logger
from pydantic import BaseModel
from sqlmodel import select

from langflow.api.utils import DbSession
from langflow.services.auth.oidc import (
    OIDCAuthenticationError,
    OIDCFederatedSession,
    authorization_url,
    create_login_state,
    decrypt_login_state,
    encrypt_federated_session,
    encrypt_login_state,
    exchange_code,
    identity_from_oidc_claims,
    resolve_provider_metadata,
    validate_id_token,
)
from langflow.services.database.models.auth.sso import SSOConfig
from langflow.services.deps import get_auth_service, get_settings_service

router = APIRouter(prefix="/sso", tags=["SSO"], include_in_schema=False)

_OIDC_STATE_COOKIE = "langflow_oidc_state"
_OIDC_STATE_COOKIE_PATH = "/api/v1/sso/"
_OIDC_FEDERATED_SESSION_COOKIE = "langflow_oidc_session"
_ASCII_CONTROL_LIMIT = 32


class SSOLoginProvider(BaseModel):
    """A provider safe to disclose to an unauthenticated login page."""

    slug: str
    display_name: str


def _oidc_enabled() -> bool:
    """Return whether browser SSO is explicitly enabled."""
    return get_settings_service().auth_settings.SSO_ENABLED


async def _get_enabled_config(session: DbSession, provider_slug: str) -> SSOConfig:
    """Load an enabled OIDC configuration without exposing disabled providers."""
    if not _oidc_enabled():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    config = (
        await session.exec(
            select(SSOConfig).where(
                SSOConfig.slug == provider_slug,
                SSOConfig.enabled == True,  # noqa: E712
            )
        )
    ).first()
    if config is None or config.protocol != "oidc":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return config


def _validated_redirect_path(value: str | None) -> str:
    """Return a same-origin application path suitable for post-login redirect."""
    fallback = get_settings_service().auth_settings.SSO_REDIRECT_URL or "/"
    path = value or fallback
    parsed = urlsplit(path)
    if (
        not path.startswith("/")
        or path.startswith("//")
        or parsed.scheme
        or parsed.netloc
        or any(character.isspace() or ord(character) < _ASCII_CONTROL_LIMIT for character in path)
    ):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid post-login redirect")
    return path


def _post_login_redirect(config: SSOConfig, redirect_path: str) -> str:
    """Resolve the saved relative path against an administrator-configured frontend origin."""
    frontend_origin = config.provider_settings.post_login_redirect_origin
    return f"{frontend_origin}{redirect_path}" if frontend_origin else redirect_path


def _matches_callback_path(request: Request, config: SSOConfig, provider_slug: str) -> bool:
    """Require the configured redirect URI to target this provider callback."""
    redirect_uri = config.provider_settings.redirect_uri
    if not redirect_uri:
        return False
    configured_path = urlsplit(redirect_uri).path
    callback_path = urlsplit(str(request.url_for("sso_callback", provider_slug=provider_slug))).path
    return configured_path == callback_path


def _set_login_cookies(response: RedirectResponse, tokens: dict, user) -> None:
    """Set the existing Langflow cookie contract after a successful OIDC login."""
    auth_settings = get_settings_service().auth_settings
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
        str(user.store_api_key or ""),
        httponly=auth_settings.ACCESS_HTTPONLY,
        samesite=auth_settings.ACCESS_SAME_SITE,
        secure=auth_settings.ACCESS_SECURE,
        domain=auth_settings.COOKIE_DOMAIN,
    )
    response.delete_cookie(
        _OIDC_STATE_COOKIE,
        httponly=True,
        samesite="lax",
        secure=auth_settings.REFRESH_SECURE,
        domain=auth_settings.COOKIE_DOMAIN,
        path=_OIDC_STATE_COOKIE_PATH,
    )


def set_federated_session_cookie(response: Response, provider_slug: str) -> None:
    """Bind the browser's Langflow session to its OIDC provider for logout."""
    auth_settings = get_settings_service().auth_settings
    response.set_cookie(
        _OIDC_FEDERATED_SESSION_COOKIE,
        encrypt_federated_session(
            OIDCFederatedSession(provider_slug=provider_slug, issued_at=int(time.time())),
            get_settings_service(),
        ),
        max_age=auth_settings.REFRESH_TOKEN_EXPIRE_SECONDS,
        httponly=True,
        samesite="lax",
        secure=auth_settings.REFRESH_SECURE,
        domain=auth_settings.COOKIE_DOMAIN,
        path="/",
    )


def _clear_state_cookie(response: RedirectResponse) -> None:
    """Delete a consumed or invalid browser login state cookie."""
    auth_settings = get_settings_service().auth_settings
    response.delete_cookie(
        _OIDC_STATE_COOKIE,
        httponly=True,
        samesite="lax",
        secure=auth_settings.REFRESH_SECURE,
        domain=auth_settings.COOKIE_DOMAIN,
        path=_OIDC_STATE_COOKIE_PATH,
    )


@router.get("/providers", response_model=list[SSOLoginProvider])
async def list_sso_login_providers(session: DbSession) -> list[SSOLoginProvider]:
    """List enabled browser SSO providers without disclosing connection configuration."""
    if not _oidc_enabled():
        return []
    configs = await session.exec(
        select(SSOConfig)
        .where(
            SSOConfig.enabled == True,  # noqa: E712
            SSOConfig.protocol == "oidc",
        )
        .order_by(SSOConfig.sort_order, SSOConfig.display_name, SSOConfig.slug)
    )
    return [
        SSOLoginProvider(slug=config.slug, display_name=config.display_name)
        for config in configs.all()
    ]


@router.get("/{provider_slug}/login")
async def begin_sso_login(
    request: Request,
    provider_slug: str,
    session: DbSession,
    next_path: Annotated[str | None, Query(alias="next", max_length=2048)] = None,
) -> RedirectResponse:
    """Redirect the browser to an enabled OIDC provider using Authorization Code with PKCE."""
    config = await _get_enabled_config(session, provider_slug)
    if not _matches_callback_path(request, config, provider_slug):
        await logger.awarning("OIDC provider configuration has an invalid callback path: provider=%s", provider_slug)
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="SSO login is unavailable")

    settings = config.provider_settings
    if not settings.client_id or not settings.redirect_uri:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="SSO login is unavailable")
    state = create_login_state(provider_slug, _validated_redirect_path(next_path))
    try:
        metadata = await resolve_provider_metadata(config)
    except OIDCAuthenticationError:
        await logger.awarning("OIDC provider metadata resolution failed: provider=%s", provider_slug)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="SSO login is unavailable"
        ) from None

    response = RedirectResponse(
        authorization_url(
            metadata,
            client_id=settings.client_id,
            redirect_uri=settings.redirect_uri,
            scopes=settings.scopes or "openid email profile",
            state=state,
        ),
        status_code=status.HTTP_303_SEE_OTHER,
    )
    auth_settings = get_settings_service().auth_settings
    response.set_cookie(
        _OIDC_STATE_COOKIE,
        encrypt_login_state(state, get_settings_service()),
        max_age=300,
        httponly=True,
        samesite="lax",
        secure=auth_settings.REFRESH_SECURE,
        domain=auth_settings.COOKIE_DOMAIN,
        path=_OIDC_STATE_COOKIE_PATH,
    )
    return response


@router.get("/{provider_slug}/callback", name="sso_callback")
async def complete_sso_login(
    request: Request,
    provider_slug: str,
    session: DbSession,
    code: Annotated[str | None, Query(max_length=4096)] = None,
    state: Annotated[str | None, Query(max_length=512)] = None,
    error: Annotated[str | None, Query(max_length=256)] = None,
) -> RedirectResponse:
    """Validate an OIDC callback, provision the user, and create a Langflow session."""
    error_response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    if error or not code or not state:
        _clear_state_cookie(error_response)
        return error_response

    encrypted_state = request.cookies.get(_OIDC_STATE_COOKIE)
    if encrypted_state is None:
        _clear_state_cookie(error_response)
        return error_response
    try:
        login_state = decrypt_login_state(encrypted_state, get_settings_service())
    except OIDCAuthenticationError:
        _clear_state_cookie(error_response)
        return error_response
    if not (
        secrets.compare_digest(login_state.provider_slug, provider_slug)
        and secrets.compare_digest(login_state.state, state)
    ):
        _clear_state_cookie(error_response)
        return error_response

    config = await _get_enabled_config(session, provider_slug)
    if not _matches_callback_path(request, config, provider_slug):
        _clear_state_cookie(error_response)
        await logger.awarning("OIDC provider callback path mismatch: provider=%s", provider_slug)
        return error_response
    settings = config.provider_settings
    if not settings.client_id:
        _clear_state_cookie(error_response)
        return error_response

    try:
        metadata = await resolve_provider_metadata(config)
        token_response = await exchange_code(config, metadata, code=code, verifier=login_state.verifier)
        claims = await validate_id_token(
            token_response["id_token"],
            metadata,
            client_id=settings.client_id,
            nonce=login_state.nonce,
        )
        identity = identity_from_oidc_claims(config, claims)
        auth = get_auth_service()
        user = await auth.get_or_create_user_from_identity(identity, session)
        tokens = await auth.create_user_tokens(user.id, session, update_last_login=True)
    except OIDCAuthenticationError:
        _clear_state_cookie(error_response)
        await logger.awarning("OIDC login failed: provider=%s", provider_slug)
        return error_response

    response = RedirectResponse(
        _post_login_redirect(config, login_state.redirect_path),
        status_code=status.HTTP_303_SEE_OTHER,
    )
    _set_login_cookies(response, tokens, user)
    set_federated_session_cookie(response, provider_slug)
    await logger.ainfo("OIDC login completed: provider=%s user_id=%s", provider_slug, user.id)
    return response
