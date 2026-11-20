"""Declarative startup synchronization for persisted browser SSO providers."""

from __future__ import annotations

import os
import re
from pathlib import Path

import yaml
from lfx.log.logger import logger
from pydantic import BaseModel, ConfigDict, model_validator
from sqlalchemy.exc import IntegrityError
from sqlmodel import select

from langflow.services.database.models.auth.sso import SSOConfig, SSOConfigCreate, SSOConfigUpdate
from langflow.services.deps import get_settings_service, session_scope

_ENVIRONMENT_REFERENCE_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class SSOBootstrapConfigurationError(ValueError):
    """Raised when declarative SSO configuration cannot be safely applied."""


class SSOBootstrapProvider(SSOConfigCreate):
    """A persisted SSO configuration with its immutable bootstrap key required."""

    slug: str


class SSOBootstrapDocument(BaseModel):
    """Strict schema for the ConfigMap-mounted SSO provider document."""

    model_config = ConfigDict(extra="forbid")

    providers: list[SSOBootstrapProvider]

    @model_validator(mode="after")
    def validate_unique_slugs(self) -> SSOBootstrapDocument:
        slugs = [provider.slug for provider in self.providers]
        if len(slugs) != len(set(slugs)):
            msg = "SSO bootstrap configuration contains duplicate provider slugs"
            raise ValueError(msg)
        return self


def _expand_environment_references(value: object) -> object:
    """Expand `${VARIABLE}` tokens while refusing undeclared environment values."""
    if isinstance(value, str):

        def replace(match: re.Match[str]) -> str:
            variable_name = match.group(1)
            environment_value = os.getenv(variable_name)
            if environment_value is None:
                msg = f"SSO bootstrap configuration references unset environment variable {variable_name}"
                raise SSOBootstrapConfigurationError(msg)
            return environment_value

        return _ENVIRONMENT_REFERENCE_PATTERN.sub(replace, value)
    if isinstance(value, list):
        return [_expand_environment_references(item) for item in value]
    if isinstance(value, dict):
        return {key: _expand_environment_references(item) for key, item in value.items()}
    return value


def load_sso_bootstrap_document(path: str) -> SSOBootstrapDocument:
    """Read, interpolate, and validate the declarative SSO bootstrap file."""
    try:
        source = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"Unable to read SSO bootstrap configuration at {path}"
        raise SSOBootstrapConfigurationError(msg) from exc

    try:
        raw_document = yaml.safe_load(source)
    except yaml.YAMLError as exc:
        msg = "Invalid YAML SSO bootstrap configuration"
        raise SSOBootstrapConfigurationError(msg) from exc
    if not isinstance(raw_document, dict):
        msg = "SSO bootstrap configuration must be a YAML mapping"
        raise SSOBootstrapConfigurationError(msg)

    try:
        return SSOBootstrapDocument.model_validate(_expand_environment_references(raw_document))
    except SSOBootstrapConfigurationError:
        raise
    except ValueError as exc:
        msg = "Invalid SSO bootstrap configuration"
        raise SSOBootstrapConfigurationError(msg) from exc


def _update_payload(provider: SSOBootstrapProvider) -> SSOConfigUpdate:
    """Build the mutable portion of a declarative provider configuration."""
    values: dict[str, object] = {
        "display_name": provider.display_name,
        "protocol": provider.protocol,
        "enabled": provider.enabled,
        "sort_order": provider.sort_order,
        "provider_settings": provider.provider_settings,
        "email_claim": provider.email_claim,
        "username_claim": provider.username_claim,
        "user_id_claim": provider.user_id_claim,
    }
    if provider.client_secret is not None:
        values["client_secret"] = provider.client_secret
    return SSOConfigUpdate(
        **values,
    )


async def _apply_document(document: SSOBootstrapDocument) -> tuple[int, int]:
    """Create or update every declared provider in one transaction."""
    settings_service = get_settings_service()
    created = 0
    updated = 0
    async with session_scope() as session:
        existing_configs = await session.exec(
            select(SSOConfig).where(SSOConfig.slug.in_([provider.slug for provider in document.providers]))
        )
        configs_by_slug = {config.slug: config for config in existing_configs.all()}

        for provider in document.providers:
            existing = configs_by_slug.get(provider.slug)
            if existing is None:
                session.add(provider.to_model(settings_service))
                created += 1
            else:
                _update_payload(provider).apply_to(existing, settings_service)
                updated += 1

        try:
            await session.commit()
        except IntegrityError:
            await session.rollback()
            # Other workers can enter the lifespan concurrently. Once their
            # inserts win the unique-slug race, retry solely as updates.
            existing_configs = await session.exec(
                select(SSOConfig).where(SSOConfig.slug.in_([provider.slug for provider in document.providers]))
            )
            configs_by_slug = {config.slug: config for config in existing_configs.all()}
            if len(configs_by_slug) != len(document.providers):
                raise
            for provider in document.providers:
                _update_payload(provider).apply_to(configs_by_slug[provider.slug], settings_service)
            await session.commit()
            created = 0
            updated = len(document.providers)
    return created, updated


async def bootstrap_sso_configs() -> None:
    """Synchronize ConfigMap-declared SSO providers into the database at startup."""
    config_path = get_settings_service().auth_settings.SSO_CONFIG_FILE
    if not config_path:
        return

    document = load_sso_bootstrap_document(config_path)
    created, updated = await _apply_document(document)
    await logger.ainfo("SSO bootstrap synchronized: created=%s updated=%s", created, updated)
