"""Superuser CRUD endpoints for runtime OIDC provider configuration."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, status
from lfx.log.logger import logger
from sqlalchemy.exc import IntegrityError
from sqlmodel import select

from langflow.api.utils import CurrentActiveUser, DbSession
from langflow.services.database.models.auth.sso import SSOConfig, SSOConfigCreate, SSOConfigRead, SSOConfigUpdate
from langflow.services.deps import get_settings_service

router = APIRouter(prefix="/sso/configs", tags=["SSO"])


def _require_superuser(current_user: CurrentActiveUser) -> None:
    """Reject non-superusers before SSO configuration is read or changed."""
    if not current_user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Superuser required")


async def _get_config(session: DbSession, config_id: UUID) -> SSOConfig:
    """Load one provider configuration or return the opaque not-found response."""
    config = await session.get(SSOConfig, config_id)
    if config is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SSO configuration not found")
    return config


@router.get("", response_model=list[SSOConfigRead])
async def list_sso_configs(session: DbSession, current_user: CurrentActiveUser) -> list[SSOConfigRead]:
    """List secret-free OIDC configurations for instance administrators."""
    _require_superuser(current_user)
    configs = await session.exec(select(SSOConfig).order_by(SSOConfig.sort_order, SSOConfig.display_name, SSOConfig.id))
    return [SSOConfigRead.model_validate(config) for config in configs.all()]


@router.post("", response_model=SSOConfigRead, status_code=status.HTTP_201_CREATED)
async def create_sso_config(
    payload: SSOConfigCreate,
    session: DbSession,
    current_user: CurrentActiveUser,
) -> SSOConfigRead:
    """Create a provider configuration and encrypt its client secret at rest."""
    _require_superuser(current_user)
    config = payload.to_model(get_settings_service(), actor_id=current_user.id)
    session.add(config)
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="SSO configuration already exists") from exc
    await session.refresh(config)
    await logger.ainfo("SSO configuration created: config_id=%s user_id=%s", config.id, current_user.id)
    return SSOConfigRead.model_validate(config)


@router.patch("/{config_id}", response_model=SSOConfigRead)
async def update_sso_config(
    config_id: UUID,
    payload: SSOConfigUpdate,
    session: DbSession,
    current_user: CurrentActiveUser,
) -> SSOConfigRead:
    """Update a provider configuration without exposing its encrypted secret."""
    _require_superuser(current_user)
    config = await _get_config(session, config_id)
    try:
        payload.apply_to(config, get_settings_service(), actor_id=current_user.id)
        await session.commit()
    except (IntegrityError, ValueError) as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid SSO configuration",
        ) from exc
    await session.refresh(config)
    await logger.ainfo("SSO configuration updated: config_id=%s user_id=%s", config.id, current_user.id)
    return SSOConfigRead.model_validate(config)


@router.delete("/{config_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_sso_config(
    config_id: UUID,
    session: DbSession,
    current_user: CurrentActiveUser,
) -> None:
    """Remove an OIDC provider configuration at runtime."""
    _require_superuser(current_user)
    config = await _get_config(session, config_id)
    await session.delete(config)
    await session.commit()
    await logger.ainfo("SSO configuration deleted: config_id=%s user_id=%s", config_id, current_user.id)
