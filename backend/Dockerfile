FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl git \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# fastembed is optional. If no wheel is available for this platform the build
# continues and vector memory reports itself off; recall falls back to keyword
# matching plus graph proximity.
RUN pip install --no-cache-dir "fastembed>=0.3.6,<1.0" \
 || echo "fastembed unavailable: vector memory will report off"

COPY app ./app
COPY mcp_server ./mcp_server
COPY pyproject.toml ./

RUN mkdir -p /data/outbox /data/graphify-workspaces /data/codebases

EXPOSE 8000 8765

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
