from __future__ import annotations

from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlsplit

import pytest
from langflow.api.v1 import login, sso
from langflow.services.auth.oidc import (
    OIDCAuthenticationError,
    OIDCProviderMetadata,
    authorization_url,
    create_login_state,
    decrypt_login_state,
    encrypt_login_state,
    identity_from_oidc_claims,
)
from langflow.services.database.models.auth.sso import OIDCProviderSettings, SSOConfig
from langflow.services.database.models.auth.sso_secret import encrypt_sso_client_secret
from langflow.services.deps import get_settings_service, session_scope

_CALLBACK_PATH = "/api/v1/sso/keycloak/callback"
_AUTHORIZATION_ENDPOINT = "https://keycloak.example/authorize"
_TOKEN_ENDPOINT = "https://keycloak.example/token"  # noqa: S105 - endpoint URL, not a credential
_JWKS_URI = "https://keycloak.example/certs"
_ISSUER = "https://keycloak.example/realms/langflow"
_POST_LOGOUT_REDIRECT_URI = "http://testserver/login"
_END_SESSION_ENDPOINT = "https://keycloak.example/logout"


@pytest.fixture
def oidc_settings():
    """Enable browser SSO for one test without leaking configuration."""
    auth_settings = get_settings_service().auth_settings
    original_enabled = auth_settings.SSO_ENABLED
    original_redirect = auth_settings.SSO_REDIRECT_URL
    auth_settings.SSO_ENABLED = True
    auth_settings.SSO_REDIRECT_URL = "/"
    yield auth_settings
    auth_settings.SSO_ENABLED = original_enabled
    auth_settings.SSO_REDIRECT_URL = original_redirect


def _provider_config() -> SSOConfig:
    """Build a valid enabled Keycloak-style configuration for route tests."""
    return SSOConfig(
        slug="keycloak",
        display_name="Keycloak",
        enabled=True,
        client_secret_encrypted=encrypt_sso_client_secret("client-secret"),
        provider_settings=OIDCProviderSettings(
            client_id="langflow",
            redirect_uri=f"http://testserver{_CALLBACK_PATH}",
            post_logout_redirect_uri=_POST_LOGOUT_REDIRECT_URI,
            authorization_endpoint=_AUTHORIZATION_ENDPOINT,
            token_endpoint=_TOKEN_ENDPOINT,
            jwks_uri=_JWKS_URI,
            issuer=_ISSUER,
        ),
    )


async def _insert_provider_config() -> None:
    async with session_scope() as session:
        session.add(_provider_config())
        await session.commit()


def test_login_state_is_encrypted_and_tamper_proof():
    """The browser state round-trips only with the server secret and exact bytes."""
    settings = get_settings_service()
    state = create_login_state("keycloak", "/flow/example")

    encrypted = encrypt_login_state(state, settings)

    assert state.state not in encrypted
    assert decrypt_login_state(encrypted, settings) == state

    altered_final_character = "A" if encrypted[-1] != "A" else "B"
    with pytest.raises(OIDCAuthenticationError):
        decrypt_login_state(f"{encrypted[:-1]}{altered_final_character}", settings)


def test_authorization_url_uses_pkce_nonce_and_state():
    """OIDC authorization redirects bind the callback to PKCE state and nonce."""
    state = create_login_state("keycloak", "/")
    url = authorization_url(
        OIDCProviderMetadata(
            authorization_endpoint=_AUTHORIZATION_ENDPOINT,
            token_endpoint=_TOKEN_ENDPOINT,
            jwks_uri=_JWKS_URI,
            issuer=_ISSUER,
        ),
        client_id="langflow",
        redirect_uri="https://langflow.example/api/v1/sso/keycloak/callback",
        scopes="openid email profile",
        state=state,
    )
    query = parse_qs(urlsplit(url).query)

    assert query["response_type"] == ["code"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["state"] == [state.state]
    assert query["nonce"] == [state.nonce]
    assert query["code_challenge"][0] != state.verifier


def test_identity_uses_configured_provider_and_claim_names():
    """A browser SSO identity is bound to the immutable config slug and configured claims."""
    config = _provider_config()
    config.user_id_claim = "oid"
    config.username_claim = "handle"
    config.email_claim = "mail"

    identity = identity_from_oidc_claims(
        config,
        {"oid": "keycloak-subject", "handle": "alice", "mail": "alice@example.com"},
    )

    assert identity.provider == "keycloak"
    assert identity.subject == "keycloak-subject"
    assert identity.username == "alice"
    assert identity.email == "alice@example.com"


async def test_sso_login_rejects_external_post_login_redirect(client, oidc_settings):
    """The login entry point must never redirect a browser to an attacker-controlled origin."""
    assert oidc_settings.SSO_ENABLED
    await _insert_provider_config()

    response = await client.get(
        "api/v1/sso/keycloak/login?next=https://attacker.example",
        follow_redirects=False,
    )

    assert response.status_code == 400


async def test_sso_login_providers_expose_only_enabled_public_fields(client, oidc_settings):
    """The login page can discover enabled provider labels without seeing secrets or endpoints."""
    keycloak = _provider_config()
    keycloak.sort_order = 10
    auth0 = _provider_config()
    auth0.slug = "auth0"
    auth0.display_name = "Auth0"
    auth0.sort_order = 5
    disabled = _provider_config()
    disabled.slug = "disabled"
    disabled.enabled = False

    async with session_scope() as session:
        session.add_all([keycloak, auth0, disabled])
        await session.commit()

    response = await client.get("api/v1/sso/providers")

    assert oidc_settings.SSO_ENABLED
    assert response.status_code == 200
    assert response.json() == [
        {"slug": "auth0", "display_name": "Auth0"},
        {"slug": "keycloak", "display_name": "Keycloak"},
    ]


async def test_superuser_can_manage_sso_configs_at_runtime(client, logged_in_headers_super_user):
    """Provider changes persist through the admin API and never return client secrets."""
    payload = {
        "slug": "keycloak",
        "display_name": "Keycloak",
        "client_secret": "client-secret",
        "provider_settings": {
            "protocol": "oidc",
            "client_id": "langflow",
            "discovery_url": "https://keycloak.example/realms/langflow/.well-known/openid-configuration",
            "redirect_uri": f"http://testserver{_CALLBACK_PATH}",
            "post_logout_redirect_uri": _POST_LOGOUT_REDIRECT_URI,
        },
    }

    created = await client.post("api/v1/sso/configs", json=payload, headers=logged_in_headers_super_user)

    assert created.status_code == 201
    assert created.json()["slug"] == "keycloak"
    assert "client_secret" not in created.json()
    config_id = created.json()["id"]

    updated = await client.patch(
        f"api/v1/sso/configs/{config_id}",
        json={"display_name": "Keycloak Production", "enabled": True},
        headers=logged_in_headers_super_user,
    )
    listed = await client.get("api/v1/sso/configs", headers=logged_in_headers_super_user)

    assert updated.status_code == 200
    assert updated.json()["enabled"] is True
    assert [config["display_name"] for config in listed.json()] == ["Keycloak Production"]


async def test_sso_callback_creates_langflow_session(client, oidc_settings, monkeypatch):
    """A verified OIDC callback provisions the user and issues the existing cookie session."""
    assert oidc_settings.SSO_ENABLED
    await _insert_provider_config()
    metadata = OIDCProviderMetadata(
        authorization_endpoint=_AUTHORIZATION_ENDPOINT,
        token_endpoint=_TOKEN_ENDPOINT,
        jwks_uri=_JWKS_URI,
        issuer=_ISSUER,
        end_session_endpoint=_END_SESSION_ENDPOINT,
    )
    monkeypatch.setattr(sso, "resolve_provider_metadata", AsyncMock(return_value=metadata))
    monkeypatch.setattr(sso, "exchange_code", AsyncMock(return_value={"id_token": "verified-id-token"}))
    monkeypatch.setattr(
        sso,
        "validate_id_token",
        AsyncMock(
            return_value={
                "sub": "keycloak-user-1",
                "preferred_username": "keycloak-user",
                "email": "keycloak-user@example.com",
                "nonce": "validated-by-mock",
            }
        ),
    )

    begin = await client.get("api/v1/sso/keycloak/login?next=/flow/example", follow_redirects=False)
    state = parse_qs(urlsplit(begin.headers["location"]).query)["state"][0]
    callback = await client.get(
        f"api/v1/sso/keycloak/callback?code=authorization-code&state={state}",
        follow_redirects=False,
    )

    assert begin.status_code == 303
    assert callback.status_code == 303
    assert callback.headers["location"] == "/flow/example"
    set_cookie = "\n".join(callback.headers.get_list("set-cookie"))
    assert "access_token_lf=" in set_cookie
    assert "refresh_token_lf=" in set_cookie
    assert "langflow_oidc_state=" in set_cookie
    assert "langflow_oidc_session=" in set_cookie


async def test_sso_callback_redirects_to_configured_frontend_origin(client, oidc_settings, monkeypatch):
    """A separate frontend origin receives the post-login route, never an arbitrary request origin."""
    assert oidc_settings.SSO_ENABLED
    config = _provider_config()
    config.provider_settings = config.provider_settings.model_copy(
        update={"post_login_redirect_origin": "http://localhost:3000"}
    )
    async with session_scope() as session:
        session.add(config)
        await session.commit()

    metadata = OIDCProviderMetadata(
        authorization_endpoint=_AUTHORIZATION_ENDPOINT,
        token_endpoint=_TOKEN_ENDPOINT,
        jwks_uri=_JWKS_URI,
        issuer=_ISSUER,
    )
    monkeypatch.setattr(sso, "resolve_provider_metadata", AsyncMock(return_value=metadata))
    monkeypatch.setattr(sso, "exchange_code", AsyncMock(return_value={"id_token": "verified-id-token"}))
    monkeypatch.setattr(
        sso,
        "validate_id_token",
        AsyncMock(
            return_value={
                "sub": "keycloak-user-1",
                "preferred_username": "keycloak-user",
                "email": "keycloak-user@example.com",
            }
        ),
    )

    begin = await client.get("api/v1/sso/keycloak/login?next=/home", follow_redirects=False)
    state = parse_qs(urlsplit(begin.headers["location"]).query)["state"][0]
    callback = await client.get(
        f"api/v1/sso/keycloak/callback?code=authorization-code&state={state}",
        follow_redirects=False,
    )

    assert callback.status_code == 303
    assert callback.headers["location"] == "http://localhost:3000/home"


async def test_federated_logout_clears_langflow_session_and_returns_provider_redirect(
    client, oidc_settings, monkeypatch
):
    """A browser SSO logout clears local cookies before navigating to the configured provider endpoint."""
    await _insert_provider_config()
    metadata = OIDCProviderMetadata(
        authorization_endpoint=_AUTHORIZATION_ENDPOINT,
        token_endpoint=_TOKEN_ENDPOINT,
        jwks_uri=_JWKS_URI,
        issuer=_ISSUER,
        end_session_endpoint=_END_SESSION_ENDPOINT,
    )
    monkeypatch.setattr(sso, "resolve_provider_metadata", AsyncMock(return_value=metadata))
    monkeypatch.setattr(sso, "exchange_code", AsyncMock(return_value={"id_token": "verified-id-token"}))
    monkeypatch.setattr(
        sso,
        "validate_id_token",
        AsyncMock(
            return_value={
                "sub": "keycloak-user-1",
                "preferred_username": "keycloak-user",
                "email": "keycloak-user@example.com",
            }
        ),
    )
    monkeypatch.setattr(login, "resolve_provider_metadata", AsyncMock(return_value=metadata))

    begin = await client.get("api/v1/sso/keycloak/login", follow_redirects=False)
    state = parse_qs(urlsplit(begin.headers["location"]).query)["state"][0]
    await client.get(
        f"api/v1/sso/keycloak/callback?code=authorization-code&state={state}",
        follow_redirects=False,
    )

    response = await client.post("api/v1/logout")

    assert oidc_settings.SSO_ENABLED
    assert response.status_code == 200
    assert response.json()["logout_url"] == (
        f"{_END_SESSION_ENDPOINT}?client_id=langflow&post_logout_redirect_uri=http%3A%2F%2Ftestserver%2Flogin"
    )
    set_cookie = "\n".join(response.headers.get_list("set-cookie"))
    assert "langflow_oidc_session=" in set_cookie


async def test_sso_refresh_renews_federated_session_cookie(client, oidc_settings, monkeypatch):
    """A rotating Langflow refresh keeps the browser's provider binding alive for federated logout."""
    await _insert_provider_config()
    metadata = OIDCProviderMetadata(
        authorization_endpoint=_AUTHORIZATION_ENDPOINT,
        token_endpoint=_TOKEN_ENDPOINT,
        jwks_uri=_JWKS_URI,
        issuer=_ISSUER,
    )
    monkeypatch.setattr(sso, "resolve_provider_metadata", AsyncMock(return_value=metadata))
    monkeypatch.setattr(sso, "exchange_code", AsyncMock(return_value={"id_token": "verified-id-token"}))
    monkeypatch.setattr(
        sso,
        "validate_id_token",
        AsyncMock(
            return_value={
                "sub": "keycloak-user-1",
                "preferred_username": "keycloak-user",
                "email": "keycloak-user@example.com",
            }
        ),
    )

    begin = await client.get("api/v1/sso/keycloak/login", follow_redirects=False)
    state = parse_qs(urlsplit(begin.headers["location"]).query)["state"][0]
    await client.get(
        f"api/v1/sso/keycloak/callback?code=authorization-code&state={state}",
        follow_redirects=False,
    )

    response = await client.post("api/v1/refresh")

    assert oidc_settings.SSO_ENABLED
    assert response.status_code == 200
    assert "langflow_oidc_session=" in "\n".join(response.headers.get_list("set-cookie"))
