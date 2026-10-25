#!/usr/bin/env bash
set -e

# Ensure data directories exist and are writable
mkdir -p /data/outbox /data/graphify-workspaces /data/codebases
chmod -R 777 /data 2>/dev/null || true

# Resolve port from Render environment (defaults to 10000 on Render)
PORT="${PORT:-10000}"
echo "==> Render detected port: ${PORT}"

# Remove default Debian site if present to avoid port 80 conflict
rm -f /etc/nginx/sites-enabled/default

# Update Nginx listen port and proxy_pass target
sed -i -E "s/listen [0-9]+;/listen ${PORT};/g" /etc/nginx/conf.d/default.conf
sed -i "s|proxy_pass http://backend:8000;|proxy_pass http://127.0.0.1:8000;|g" /etc/nginx/conf.d/default.conf

# Forward Nginx access and error logs to stdout/stderr so they show in Render logs
ln -sf /dev/stdout /var/log/nginx/access.log
ln -sf /dev/stderr /var/log/nginx/error.log

# Trap signals for graceful shutdown
cleanup() {
    echo "==> Shutting down services..."
    kill -TERM "$MCP_PID" "$BACKEND_PID" "$NGINX_PID" 2>/dev/null || true
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# Start Nginx FIRST so Render port detection immediately sees port $PORT open!
echo "==> Starting Nginx on port ${PORT}..."
nginx -g "daemon off;" &
NGINX_PID=$!

# Start FastMCP server in background
echo "==> Starting FastMCP server on 127.0.0.1:8765..."
python -m mcp_server.server --transport streamable-http --host 127.0.0.1 --port 8765 &
MCP_PID=$!

# Start FastAPI / Uvicorn backend in background
echo "==> Starting FastAPI backend on 127.0.0.1:8000..."
uvicorn app.main:app --host 127.0.0.1 --port 8000 --log-level info &
BACKEND_PID=$!

# Monitor processes: if any process dies, container exits cleanly
wait -n "$NGINX_PID" "$BACKEND_PID" "$MCP_PID"
