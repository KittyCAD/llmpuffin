# Stage 1: Build
FROM python:3.13-slim-bookworm AS build

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Install dependencies first (cache layer)
COPY pyproject.toml uv.lock ./
RUN uv sync --no-sources --no-dev --frozen

# Copy source
COPY src/ src/
COPY alembic.ini ./
RUN uv pip install --system --no-deps .

# Stage 2: Runtime
FROM python:3.13-slim-bookworm

RUN apt-get update && apt-get install -y \
    ca-certificates \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/local /usr/local

WORKDIR /app
COPY --from=build /app/alembic.ini ./
COPY --from=build /app/src/llmpuffin/alembic/ src/llmpuffin/alembic/

EXPOSE 8000

CMD ["llmpuffin-fastapi"]
