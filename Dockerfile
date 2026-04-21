FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir uv

# Dependency layer
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

# Source layer. Each Fly app picks its entry point via the CMD override in fly.toml.
COPY streaming ./streaming
COPY batch ./batch
COPY dashboard ./dashboard

ENV PYTHONUNBUFFERED=1
ENV PATH="/app/.venv/bin:$PATH"

CMD ["python", "--version"]
