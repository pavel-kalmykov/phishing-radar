# Stage 1 — build the venv. Throwaway; pip + uv only live here.
FROM python:3.11-slim AS builder

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev


# Stage 2 — runtime. Only the venv and the source land in the final image.
FROM python:3.11-slim AS runtime

# Non-root user. Container CVE scanners, Fly machine policy and reviewers all
# expect this; running Python as root in production is gratuitous.
RUN groupadd --system app \
  && useradd --system --gid app --home-dir /app --shell /usr/sbin/nologin app

WORKDIR /app

COPY --from=builder --chown=app:app /app/.venv /app/.venv
COPY --chown=app:app streaming ./streaming
COPY --chown=app:app batch ./batch
COPY --chown=app:app dashboard ./dashboard

ENV PYTHONUNBUFFERED=1
ENV PATH="/app/.venv/bin:$PATH"

USER app

# Each Fly app picks its entry point via the CMD override in fly.toml.
CMD ["python", "--version"]
