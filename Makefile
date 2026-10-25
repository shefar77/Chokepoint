# CHOKEPOINT. Everything runs through docker compose.

COMPOSE ?= docker compose
SCALE   ?= 1
# docker-compose publishes the backend on BACKEND_PORT; keep these in step.
BACKEND_PORT ?= 8050
API     ?= http://localhost:$(BACKEND_PORT)

.PHONY: up down seed logs mcp-stdio delta evals health rebuild typecheck lint test clean

up: ## Build and start mcp, backend and frontend
	$(COMPOSE) up --build -d
	@echo "CHOKEPOINT is starting. Open http://localhost:8080"
	@echo "API $(API)/api/health  ·  MCP server http://localhost:8765/mcp"

down: ## Stop everything and remove the containers
	$(COMPOSE) down

rebuild: ## Rebuild the images without cache
	$(COMPOSE) build --no-cache

seed: ## Drop and regenerate the graph (SCALE=1 by default)
	curl -fsS -X POST $(API)/api/seed/reset \
	  -H 'Content-Type: application/json' \
	  -d '{"scale": $(SCALE)}'
	@echo

delta: ## Apply the day-2 scan (scenario S7 and the S6 follow-up)
	curl -fsS -X POST $(API)/api/scan/delta
	@echo

evals: ## Run the evaluation and print the metrics
	curl -fsS $(API)/api/evals/run
	@echo

health: ## Print the health document
	curl -fsS $(API)/api/health
	@echo

logs: ## Follow the logs of every service
	$(COMPOSE) logs -f --tail=80

mcp-stdio: ## Run the MCP server on stdio against a local SQLite
	cd backend && SQLITE_PATH=/data/chokepoint.db \
	  python -m mcp_server.server --transport stdio

typecheck: ## TypeScript check of the frontend
	cd frontend && npm install --no-audit --no-fund && npm run typecheck

lint: ## Ruff over the Python source
	cd backend && ruff check .

test: ## Run the backend test suite (no network, no scanners, no model needed)
	cd backend && python -m pytest tests -q

clean: ## Remove containers and volumes
	$(COMPOSE) down -v