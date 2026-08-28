# SENTINEL X API + job worker image
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System deps for security tooling when mounted in (nmap etc. stay optional).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY apps/api/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY apps/api /app

EXPOSE 8000

# ENVIRONMENT != test => the in-process worker loop starts automatically.
CMD ["uvicorn", "sentinelx.main:app", "--host", "0.0.0.0", "--port", "8000"]
