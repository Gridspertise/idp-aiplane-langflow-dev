"""OIDC authorization-code helpers for browser SSO providers."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

import httpx
import jwt
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from jwt import InvalidTokenError as PyJWTInvalidTokenError

from langflow.services.auth.external import ExternalIdentity
from langflow.services.database.models.auth.sso_secret import decrypt_sso_client_secret

if TYPE_CHECKING:
    from lfx.services.settings.service import SettingsService

    from langflow.services.database.models.auth.sso import SSOConfig

_OIDC_STATE_HEADER = b"langflow/oidc/login-state/v1"
_OIDC_STATE_SALT = b"langflow/oidc/login-state/hkdf-salt/v1"
_OIDC_STATE_INFO = b"langflow/oidc/login-state/encryption"
_OIDC_SESSION_HEADER = b"langflow/oidc/federated-session/v1"
_OIDC_STATE_NONCE_BYTES = 12
_OIDC_STATE_MAX_AGE_SECONDS = 300
_HTTP_TIMEOUT_SECONDS = 10.0
_B64URL_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


class OIDCAuthenticationError(ValueError):
    """Raised when an OIDC provider response cannot establish a safe session."""

    def __init__(self) -> None:
        """Expose one non-disclosing OIDC error to callers."""
        super().__init__("OIDC authentication failed")


@dataclass(frozen=True, slots=True)
class OIDCLoginState:
    """One browser login attempt, stored encrypted in a short-lived cookie."""

    provider_slug: str
    state: str
    nonce: str
    verifier: str
    redirect_path: str
    issued_at: int

    def to_json(self) -> bytes:
        """Serialize a state payload without exposing it outside encrypted storage."""
        return json.dumps(
            {
                "provider_slug": self.provider_slug,
                "state": self.state,
                "nonce": self.nonce,
                "verifier": self.verifier,
                "redirect_path": self.redirect_path,
                "issued_at": self.issued_at,
            },
            separators=(",", ":"),
        ).encode()

    @classmethod
    def from_json(cls, payload: bytes) -> OIDCLoginState:
        """Parse and validate a decrypted login state."""
        try:
            value = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OIDCAuthenticationError from exc
        if not isinstance(value, dict):
            raise OIDCAuthenticationError
        required = ("provider_slug", "state", "nonce", "verifier", "redirect_path", "issued_at")
        valid_strings = all(isinstance(value.get(key), str) for key in required[:-1])
        if not valid_strings or not isinstance(value.get("issued_at"), int):
            raise OIDCAuthenticationError
        return cls(**{key: value[key] for key in required})


@dataclass(frozen=True, slots=True)
class OIDCProviderMetadata:
    """Endpoints and issuer required for one OIDC authorization-code exchange."""

    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    issuer: str
    end_session_endpoint: str | None = None


@dataclass(frozen=True, slots=True)
class OIDCFederatedSession:
    """The provider that authenticated the current browser session."""

    provider_slug: str
    issued_at: int

    def to_json(self) -> bytes:
        """Serialize the minimal provider binding needed for federated logout."""
        return json.dumps(
            {"provider_slug": self.provider_slug, "issued_at": self.issued_at},
            separators=(",", ":"),
        ).encode()

    @classmethod
    def from_json(cls, payload: bytes) -> OIDCFederatedSession:
        """Parse a decrypted federated-session binding."""
        try:
            value = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OIDCAuthenticationError from exc
        if not isinstance(value, dict) or not isinstance(value.get("provider_slug"), str):
            raise OIDCAuthenticationError
        if not isinstance(value.get("issued_at"), int):
            raise OIDCAuthenticationError
        return cls(provider_slug=value["provider_slug"], issued_at=value["issued_at"])


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _decode(value: str) -> bytes:
    if not value or any(character not in _B64URL_ALPHABET for character in value):
        raise OIDCAuthenticationError
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except ValueError as exc:
        raise OIDCAuthenticationError from exc
    if _encode(decoded) != value:
        raise OIDCAuthenticationError
    return decoded


def _state_key(settings_service: SettingsService) -> bytes:
    secret_key = settings_service.auth_settings.SECRET_KEY.get_secret_value()
    if not secret_key:
        raise OIDCAuthenticationError
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_OIDC_STATE_SALT,
        info=_OIDC_STATE_INFO,
    ).derive(secret_key.encode())


def _code_challenge(verifier: str) -> str:
    return _encode(hashlib.sha256(verifier.encode()).digest())


def create_login_state(provider_slug: str, redirect_path: str) -> OIDCLoginState:
    """Create the state, nonce, and PKCE verifier for one browser login."""
    return OIDCLoginState(
        provider_slug=provider_slug,
        state=secrets.token_urlsafe(32),
        nonce=secrets.token_urlsafe(32),
        verifier=secrets.token_urlsafe(64),
        redirect_path=redirect_path,
        issued_at=int(time.time()),
    )


def encrypt_federated_session(session: OIDCFederatedSession, settings_service: SettingsService) -> str:
    """Encrypt a minimal federated-session binding for an HttpOnly cookie."""
    nonce = secrets.token_bytes(_OIDC_STATE_NONCE_BYTES)
    ciphertext = AESGCM(_state_key(settings_service)).encrypt(nonce, session.to_json(), _OIDC_SESSION_HEADER)
    return f"{_encode(nonce)}.{_encode(ciphertext)}"


def decrypt_federated_session(
    value: str, settings_service: SettingsService, *, max_age_seconds: int
) -> OIDCFederatedSession:
    """Decrypt a federated-session binding and reject expired or malformed values."""
    try:
        encoded_nonce, encoded_ciphertext = value.split(".", maxsplit=1)
        nonce = _decode(encoded_nonce)
        ciphertext = _decode(encoded_ciphertext)
        payload = AESGCM(_state_key(settings_service)).decrypt(nonce, ciphertext, _OIDC_SESSION_HEADER)
    except (InvalidTag, ValueError) as exc:
        raise OIDCAuthenticationError from exc
    if len(nonce) != _OIDC_STATE_NONCE_BYTES:
        raise OIDCAuthenticationError
    session = OIDCFederatedSession.from_json(payload)
    now = int(time.time())
    if session.issued_at > now or now - session.issued_at > max_age_seconds:
        raise OIDCAuthenticationError
    return session


def encrypt_login_state(state: OIDCLoginState, settings_service: SettingsService) -> str:
    """Encrypt a browser login state for storage in an HttpOnly cookie."""
    nonce = secrets.token_bytes(_OIDC_STATE_NONCE_BYTES)
    ciphertext = AESGCM(_state_key(settings_service)).encrypt(nonce, state.to_json(), _OIDC_STATE_HEADER)
    return f"{_encode(nonce)}.{_encode(ciphertext)}"


def decrypt_login_state(value: str, settings_service: SettingsService) -> OIDCLoginState:
    """Decrypt and expire-check an OIDC browser login state."""
    try:
        encoded_nonce, encoded_ciphertext = value.split(".", maxsplit=1)
        nonce = _decode(encoded_nonce)
        ciphertext = _decode(encoded_ciphertext)
        payload = AESGCM(_state_key(settings_service)).decrypt(nonce, ciphertext, _OIDC_STATE_HEADER)
    except (InvalidTag, ValueError) as exc:
        raise OIDCAuthenticationError from exc
    if len(nonce) != _OIDC_STATE_NONCE_BYTES:
        raise OIDCAuthenticationError
    state = OIDCLoginState.from_json(payload)
    now = int(time.time())
    if state.issued_at > now or now - state.issued_at > _OIDC_STATE_MAX_AGE_SECONDS:
        raise OIDCAuthenticationError
    return state


async def resolve_provider_metadata(config: SSOConfig) -> OIDCProviderMetadata:
    """Resolve and validate endpoints from explicit settings or OIDC discovery."""
    settings = config.provider_settings
    explicit = (
        settings.authorization_endpoint,
        settings.token_endpoint,
        settings.jwks_uri,
        settings.issuer,
    )
    if all(explicit):
        return OIDCProviderMetadata(
            authorization_endpoint=settings.authorization_endpoint,
            token_endpoint=settings.token_endpoint,
            jwks_uri=settings.jwks_uri,
            issuer=settings.issuer,
        )
    if not settings.discovery_url:
        raise OIDCAuthenticationError
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_SECONDS, follow_redirects=False) as client:
            response = await client.get(settings.discovery_url)
            response.raise_for_status()
            document = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OIDCAuthenticationError from exc
    if not isinstance(document, dict):
        raise OIDCAuthenticationError
    values = tuple(document.get(key) for key in ("authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"))
    if not all(isinstance(value, str) and value for value in values):
        raise OIDCAuthenticationError
    end_session_endpoint = document.get("end_session_endpoint")
    if end_session_endpoint is not None and not isinstance(end_session_endpoint, str):
        raise OIDCAuthenticationError
    return OIDCProviderMetadata(*values, end_session_endpoint=end_session_endpoint)


def end_session_url(config: SSOConfig, metadata: OIDCProviderMetadata) -> str | None:
    """Build a provider logout URL only when the administrator configured a return URI."""
    settings = config.provider_settings
    if not metadata.end_session_endpoint or not settings.client_id or not settings.post_logout_redirect_uri:
        return None
    query = urlencode(
        {
            "client_id": settings.client_id,
            "post_logout_redirect_uri": settings.post_logout_redirect_uri,
        }
    )
    return f"{metadata.end_session_endpoint}?{query}"


def authorization_url(
    metadata: OIDCProviderMetadata,
    *,
    client_id: str,
    redirect_uri: str,
    scopes: str,
    state: OIDCLoginState,
) -> str:
    """Build an OIDC authorization URL using PKCE and a nonce."""
    return f"{metadata.authorization_endpoint}?{
        urlencode(
            {
                'client_id': client_id,
                'redirect_uri': redirect_uri,
                'response_type': 'code',
                'scope': scopes,
                'state': state.state,
                'nonce': state.nonce,
                'code_challenge': _code_challenge(state.verifier),
                'code_challenge_method': 'S256',
            }
        )
    }"


async def exchange_code(
    config: SSOConfig,
    metadata: OIDCProviderMetadata,
    *,
    code: str,
    verifier: str,
) -> dict[str, Any]:
    """Exchange an authorization code without exposing provider response details."""
    if not config.client_secret_encrypted:
        raise OIDCAuthenticationError
    try:
        client_secret = decrypt_sso_client_secret(config.client_secret_encrypted)
    except ValueError as exc:
        raise OIDCAuthenticationError from exc
    settings = config.provider_settings
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_SECONDS, follow_redirects=False) as client:
            response = await client.post(
                metadata.token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": settings.redirect_uri or "",
                    "client_id": settings.client_id or "",
                    "client_secret": client_secret,
                    "code_verifier": verifier,
                },
            )
            response.raise_for_status()
            token_response = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OIDCAuthenticationError from exc
    if not isinstance(token_response, dict) or not isinstance(token_response.get("id_token"), str):
        raise OIDCAuthenticationError
    return token_response


async def validate_id_token(
    id_token: str,
    metadata: OIDCProviderMetadata,
    *,
    client_id: str,
    nonce: str,
) -> dict[str, Any]:
    """Verify an ID token against the configured issuer, audience, JWKS, and nonce."""
    try:
        headers = jwt.get_unverified_header(id_token)
        kid = headers.get("kid")
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_SECONDS, follow_redirects=False) as client:
            response = await client.get(metadata.jwks_uri)
            response.raise_for_status()
            jwks = response.json()
        keys = jwks.get("keys") if isinstance(jwks, dict) else None
        if not isinstance(keys, list):
            raise OIDCAuthenticationError
        matching = [key for key in keys if isinstance(key, dict) and (kid is None or key.get("kid") == kid)]
        if len(matching) != 1:
            raise OIDCAuthenticationError
        signing_key = jwt.PyJWK.from_dict(matching[0]).key
        claims = jwt.decode(
            id_token,
            signing_key,
            algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
            audience=client_id,
            issuer=metadata.issuer,
            options={"require": ["exp", "iat", "sub"]},
        )
    except OIDCAuthenticationError:
        raise
    except (httpx.HTTPError, PyJWTInvalidTokenError, ValueError) as exc:
        raise OIDCAuthenticationError from exc
    if claims.get("nonce") != nonce:
        raise OIDCAuthenticationError
    return claims


def identity_from_oidc_claims(config: SSOConfig, claims: dict[str, Any]) -> ExternalIdentity:
    """Normalize verified OIDC claims according to a provider configuration."""

    def claim_value(name: str) -> str | None:
        value = claims.get(name)
        if value is None:
            return None
        result = value.strip() if isinstance(value, str) else str(value).strip()
        return result or None

    subject = claim_value(config.user_id_claim)
    if not subject:
        raise OIDCAuthenticationError
    email = claim_value(config.email_claim)
    username = claim_value(config.username_claim) or email or f"{config.slug}-{subject[:12]}"
    name = claim_value("name")
    return ExternalIdentity(
        provider=config.slug,
        subject=subject,
        username=username[:255],
        email=email,
        name=name,
        claims=claims,
    )
