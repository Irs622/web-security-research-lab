.PHONY: up down ps logs test-baseline test-waf analyze charts test-unit zap help

help:
	@echo "WAF Research Lab - Command Shortcuts"
	@echo "  make up            : Start Juice Shop and ModSecurity WAF containers"
	@echo "  make down          : Stop all containers"
	@echo "  make ps            : Check status of running containers and health checks"
	@echo "  make logs          : Tail logs from WAF and Juice Shop"
	@echo "  make test-unit     : Run pytest unit test suite"
	@echo "  make test-baseline : Run controlled test suite against baseline direct endpoint"
	@echo "  make test-waf      : Run controlled test suite against WAF inspected endpoint"
	@echo "  make analyze       : Compute confusion matrix, detection, blocking rates, and latency"
	@echo "  make charts        : Generate PNG charts and figures for thesis"
	@echo "  make zap           : Run OWASP ZAP passive baseline scan"

up:
	docker compose up -d juice-shop waf

down:
	docker compose down

ps:
	docker compose ps

logs:
	docker compose logs --tail=100 waf juice-shop

test-unit:
	.venv/bin/pytest -v

test-baseline:
	python3 simulator/run_tests.py --target http://127.0.0.1:3001 --mode baseline

test-waf:
	python3 simulator/run_tests.py --target http://127.0.0.1:8080 --mode waf

analyze:
	python3 evaluation/analyze_results.py

charts:
	.venv/bin/python evaluation/generate_charts.py

zap:
	docker compose --profile scan run --rm zap-baseline

# --- Production deployment (lihat docs/PRODUCTION.md) ---
PROD = docker compose -f deploy/prod/docker-compose.prod.yml --env-file deploy/prod/.env

.PHONY: prod-up prod-down prod-restart prod-logs prod-fp install

install:
	python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

prod-up:
	$(PROD) up -d

prod-down:
	$(PROD) down

prod-restart:
	$(PROD) restart waf

prod-logs:
	$(PROD) logs --tail=100 -f waf

prod-fp:
	@$(PROD) exec waf sh -c "cat /var/log/modsecurity/audit.log" \
	  | grep -o '"ruleId":"[0-9]*"' | sort | uniq -c | sort -rn | head -20
