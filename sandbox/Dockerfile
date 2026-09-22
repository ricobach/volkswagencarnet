FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/workspace

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY requirements.txt ./

# Install only third-party dependencies into the image. The actual
# volkswagencarnet source is bind-mounted at /workspace by Compose, so Python
# code changes are picked up immediately without rebuilding the image.
RUN python -m pip install --upgrade pip \
    && python -m pip install --no-cache-dir -r requirements.txt

WORKDIR /workspace

ENTRYPOINT ["python", "sandbox/test_auth.py"]
