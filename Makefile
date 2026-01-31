\
SHELL := /bin/bash
PROJECT := security-logging-lab

# Connection string for local psql
DB_URL := postgresql://postgres:postgres@localhost:5432/security_logs

.PHONY: help up down reset logs ps psql checks

help:
	@echo ""
	@echo "$(PROJECT) commands:"
	@echo "  make up      - start postgres + pgadmin"
	@echo "  make down    - stop containers"
	@echo "  make reset   - stop + delete volumes (fresh DB + re-run init scripts)"
	@echo "  make ps      - show container status"
	@echo "  make logs    - tail logs"
	@echo "  make psql    - open psql shell (requires psql installed)"
	@echo "  make checks  - run security_checks.sql against local DB (requires psql)"
	@echo ""

up:
	docker compose up -d

down:
	docker compose down

reset:
	docker compose down -v
	docker compose up -d

ps:
	docker compose ps

logs:
	docker compose logs -f --tail=200

psql:
	psql "$(DB_URL)"

checks:
	psql "$(DB_URL)" -f queries/security_checks.sql
