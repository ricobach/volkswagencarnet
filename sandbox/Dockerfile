FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

COPY requirements.txt setup.cfg pyproject.toml README.md ./
COPY volkswagencarnet ./volkswagencarnet

RUN python -m pip install --upgrade pip \
    && python -m pip install --no-cache-dir -e .

WORKDIR /workspace

ENTRYPOINT ["python", "sandbox/test_auth.py"]
