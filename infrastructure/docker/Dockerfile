# syntax=docker/dockerfile:1
# CI build context layout:
# Context = infrastructure/docker + contents of src/ (as assembled by the build task).
# Simulate: mkdir /tmp/ctx && cp -R infrastructure/docker/. /tmp/ctx && cp -R src/. /tmp/ctx && docker build -t langflow:ci /tmp/ctx

ARG UV_VERSION=0.10.4
ARG PYTHON_IMAGE=registry.access.redhat.com/ubi10/python-314-minimal
ARG NODE_VERSION=24.22.1

FROM ghcr.io/astral-sh/uv:${UV_VERSION} AS uv-installer

FROM ${PYTHON_IMAGE} AS builder-base

USER root
ARG NODE_VERSION

COPY --from=uv-installer /uv /usr/local/bin/uv

RUN microdnf install -y curl gcc gcc-c++ git make python3.14-devel tar xz \
    && ARCH=$(uname -m) \
    && case "$ARCH" in \
        x86_64) NODE_ARCH=x64 ;; \
        aarch64) NODE_ARCH=arm64 ;; \
        *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; \
    esac \
    && curl -fsSLo /tmp/node.tar.xz \
        "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz" \
    && tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1 \
    && rm -f /tmp/node.tar.xz \
    && microdnf clean all

WORKDIR /app

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    RUSTFLAGS="--cfg reqwest_unstable"

FROM builder-base AS frontend-builder

WORKDIR /app/src/frontend

COPY frontend/package.json frontend/package-lock.json ./

RUN --mount=type=cache,target=/root/.npm \
    PUPPETEER_SKIP_DOWNLOAD=true npm ci

COPY frontend/ ./

RUN ESBUILD_BINARY_PATH="" NODE_OPTIONS="--max-old-space-size=4096" JOBS=1 npm run build \
    && test -s build/index.html

FROM builder-base AS backend-builder

COPY pyproject.toml uv.lock README.md ./
COPY backend/base/pyproject.toml backend/base/README.md ./src/backend/base/
COPY lfx/pyproject.toml lfx/README.md ./src/lfx/
COPY sdk/pyproject.toml sdk/README.md ./src/sdk/
COPY langflow-stepflow/pyproject.toml langflow-stepflow/README.md ./src/langflow-stepflow/
COPY bundles/ ./src/bundles/

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --extra postgresql --extra pgvector --no-default-groups --no-install-workspace

COPY backend/ ./src/backend/
COPY lfx/ ./src/lfx/
COPY sdk/ ./src/sdk/
COPY langflow-stepflow/ ./src/langflow-stepflow/
COPY --from=frontend-builder /app/src/frontend/build/ ./src/backend/base/langflow/frontend/

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --extra postgresql --extra pgvector --no-default-groups --no-editable \
    && uv pip check --python /app/.venv/bin/python \
    && test -x /app/.venv/bin/langflow \
    && /app/.venv/bin/python -c \
        'from importlib.resources import files; assert files("langflow").joinpath("frontend/index.html").is_file(), "Packaged frontend is missing"'

FROM ${PYTHON_IMAGE} AS runtime

USER root

RUN microdnf update -y \
    && microdnf install -y curl git gnupg libpq shadow-utils tar xz \
    && microdnf clean all

COPY --from=builder-base /usr/local/bin/uv /usr/local/bin/uv
COPY --from=uv-installer /uvx /usr/local/bin/uvx
COPY --from=builder-base /usr/local/bin/node /usr/local/bin/node
COPY --from=builder-base /usr/local/lib/node_modules /usr/local/lib/node_modules

RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
    && useradd user -u 1000 -g 0 --no-create-home --home-dir /app/data \
    && mkdir -p /app/data /app/langflow /app/.npm \
    && chown -R 1000:0 /app/data /app/langflow /app/.npm \
    && chmod -R g+rwX /app/data /app/langflow /app/.npm

WORKDIR /app

COPY --from=backend-builder --chown=1000:0 /app/.venv /app/.venv

ENV PATH="/app/.venv/bin:$PATH" \
    HOME=/app/data \
    BASH_ENV="" \
    ENV="" \
    PROMPT_COMMAND="" \
    NPM_CONFIG_CACHE=/app/.npm \
    LANGFLOW_HOST=0.0.0.0 \
    LANGFLOW_PORT=7860 \
    LANGFLOW_AUTO_LOGIN=false

USER 1000

EXPOSE 7860

CMD ["langflow", "run"]
