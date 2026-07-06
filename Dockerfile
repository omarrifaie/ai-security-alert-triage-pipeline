# ---- Builder: compile and install the package + deps into an isolated venv ----
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# build-essential / libpq-dev are only needed to build wheels; they stay in
# this stage and never reach the runtime image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install .

# ---- Runtime: copy only the populated venv into a slim image ----
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY alembic ./alembic
COPY alembic.ini ./alembic.ini

RUN useradd --create-home --shell /bin/bash app \
    && chown -R app:app /app
USER app

EXPOSE 8000

# Python-based healthcheck so we don't have to ship curl in the runtime image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health', timeout=4).status == 200 else 1)" || exit 1

CMD ["uvicorn", "ai_triage.dashboard.app:app", "--host", "0.0.0.0", "--port", "8000"]
