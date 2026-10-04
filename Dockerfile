FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Exercise both transports so missing runtime dependencies fail during build.
RUN python -c 'import tls_client; from curl_cffi import requests; tls_client.Session(client_identifier="okhttp4_android_13")'
COPY app/ ./app/
COPY LICENSE THIRD_PARTY_NOTICES.md PRIVACY.md ./legal/
COPY licenses/ ./legal/licenses/
RUN python -c 'import app.setup; import app.service; import discord'
ENV AUTH_STATE_DIR=/data AUTH_CONFIG=/config/config.toml PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
CMD ["python", "-m", "app.service"]
