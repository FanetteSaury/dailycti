FROM python:3.11-slim AS base

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv for fast dependency management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy dependency files
COPY pyproject.toml ./

# Install dependencies
RUN uv pip install --system -e ".[dev]"

# Download spaCy model
RUN python -m spacy download en_core_web_trf

# Production stage
FROM base AS production

# Copy application code
COPY src/ ./src/
COPY config/ ./config/
COPY templates/ ./templates/

# Create archive directory
RUN mkdir -p /app/archive

# Default command: run full pipeline
CMD ["fidlie", "run"]
