from __future__ import annotations

import pytest
from langflow.services.auth.sso_bootstrap import (
    SSOBootstrapConfigurationError,
    bootstrap_sso_configs,
    load_sso_bootstrap_document,
)
from langflow.services.database.models.auth.sso import SSOConfig
from langflow.services.deps import get_settings_service, session_scope
from sqlmodel import select

_CONFIGURATION = """
providers:
  - slug: keycloak
    display_name: Keycloak
    enabled: true
    client_secret: ${KEYCLOAK_CLIENT_SECRET}
    provider_settings:
      protocol: oidc
      client_id: ${KEYCLOAK_CLIENT_ID}
      discovery_url: ${KEYCLOAK_DISCOVERY_URL}
      redirect_uri: ${KEYCLOAK_REDIRECT_URI}
"""


def _configure_keycloak_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KEYCLOAK_CLIENT_SECRET", "client-secret")
    monkeypatch.setenv("KEYCLOAK_CLIENT_ID", "langflow")
    monkeypatch.setenv(
        "KEYCLOAK_DISCOVERY_URL",
        "https://keycloak.example/realms/langflow/.well-known/openid-configuration",
    )
    monkeypatch.setenv("KEYCLOAK_REDIRECT_URI", "https://langflow.example/api/v1/sso/keycloak/callback")


def test_sso_bootstrap_interpolates_environment_references(tmp_path, monkeypatch):
    """A ConfigMap document can use Secret-injected environment variables."""
    _configure_keycloak_environment(monkeypatch)
    config_path = tmp_path / "sso.yaml"
    config_path.write_text(_CONFIGURATION, encoding="utf-8")

    document = load_sso_bootstrap_document(str(config_path))

    provider = document.providers[0]
    assert provider.slug == "keycloak"
    assert provider.client_secret is not None
    assert provider.client_secret.get_secret_value() == "client-secret"
    assert provider.provider_settings.client_id == "langflow"


def test_sso_bootstrap_rejects_unset_environment_references(tmp_path, monkeypatch):
    """A missing Secret-injected variable aborts startup without exposing its value."""
    _configure_keycloak_environment(monkeypatch)
    monkeypatch.delenv("KEYCLOAK_CLIENT_SECRET")
    config_path = tmp_path / "sso.yaml"
    config_path.write_text(_CONFIGURATION, encoding="utf-8")

    with pytest.raises(SSOBootstrapConfigurationError, match="KEYCLOAK_CLIENT_SECRET"):
        load_sso_bootstrap_document(str(config_path))


@pytest.mark.usefixtures("client")
async def test_sso_bootstrap_upserts_configured_providers(tmp_path, monkeypatch):
    """Repeated startup synchronization updates one stable provider row."""
    _configure_keycloak_environment(monkeypatch)
    config_path = tmp_path / "sso.yaml"
    config_path.write_text(_CONFIGURATION, encoding="utf-8")
    auth_settings = get_settings_service().auth_settings
    original_config_path = auth_settings.SSO_CONFIG_FILE
    auth_settings.SSO_CONFIG_FILE = str(config_path)

    try:
        await bootstrap_sso_configs()

        updated_configuration = _CONFIGURATION.replace("display_name: Keycloak", "display_name: Company Keycloak")
        config_path.write_text(updated_configuration, encoding="utf-8")
        await bootstrap_sso_configs()
    finally:
        auth_settings.SSO_CONFIG_FILE = original_config_path

    async with session_scope() as session:
        configs = (await session.exec(select(SSOConfig).where(SSOConfig.slug == "keycloak"))).all()

    assert len(configs) == 1
    assert configs[0].display_name == "Company Keycloak"
    assert configs[0].client_secret_encrypted is not None
