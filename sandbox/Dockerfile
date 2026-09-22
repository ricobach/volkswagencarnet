FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY requirements.txt setup.cfg pyproject.toml README.md ./
COPY volkswagencarnet ./volkswagencarnet

RUN python -m pip install --upgrade pip \
    && python -m pip install --no-cache-dir -e .

WORKDIR /workspace

ENTRYPOINT ["python", "sandbox/test_auth.py"]
