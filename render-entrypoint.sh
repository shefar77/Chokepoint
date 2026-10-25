#!/usr/bin/env bash
set -e

# Ensure runtime directories exist
mkdir -p /data/outbox /data/graphify-workspaces /data/codebases

# Resolve port from Render environment (defaults to 10000 on Render, fallback to 8080)
PORT="${PORT:-10000}"
echo "==> Configuring Nginx to listen on port ${PORT} and proxy to 127.0.0.1:8000..."

# Update Nginx listen port and proxy_pass target
sed -i -E "s/listen [0-9]+;/listen ${PORT};/g" /etc/nginx/conf.d/default.conf
sed -i "s|proxy_pass http://backend:8000;|proxy_pass http://127.0.0.1:8000;|g" /etc/nginx/conf.d/default.conf

# Trap termination signals to kill background processes gracefully
cleanup() {
    echo "==> Shutting down services..."
    kill -TERM "$MCP_PID" "$BACKEND_PID" 2>/dev/null || true
    wait "$MCP_PID" 2>/dev/null || true
    wait "$BACKEND_PID" 2>/dev/null || true
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# Start FastMCP server in background
echo "==> Starting FastMCP server on 127.0.0.1:8765..."
python -m mcp_server.server --transport streamable-http --host 127.0.0.1 --port 8765 &
MCP_PID=$!

# Wait briefly for MCP port to become ready
sleep 2

# Start Uvicorn backend in background
echo "==> Starting FastAPI / Uvicorn backend on 127.0.0.1:8000..."
uvicorn app.main:app --host 127.0.0.1 --port 8000 --log-level info &
BACKEND_PID=$!

# Wait for backend health to be reachable
echo "==> Waiting for FastAPI and MCP readiness..."
for i in {1..30}; do
    if curl -fsS http://127.0.0.1:8000/api/health >/dev/null 2>&1; then
        echo "==> Backend is healthy and ready!"
        break
    fi
    sleep 1
done

# Start Nginx in foreground as the main container process
echo "==> Starting Nginx in foreground on port ${PORT}..."
exec nginx -g "daemon off;"
