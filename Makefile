.PHONY: up down ps logs test-baseline test-waf analyze charts test-unit lint zap help check
.DEFAULT_GOAL := help

REPEAT ?= 3
# Prefer the project venv (make install) so every target uses the same interpreter and deps.
PY ?= $(shell test -x .venv/bin/python && echo .venv/bin/python || echo python3)

help:
	@echo "WAF Research Lab - Command Shortcuts"
	@echo "  make install       : Create .venv and install Python dependencies"
	@echo "  make check         : Lint + unit tests (run before committing)"
	@echo "  make up            : Start Juice Shop and ModSecurity WAF containers"
	@echo "  make down          : Stop all containers"
	@echo "  make ps            : Check status of running containers and health checks"
	@echo "  make logs          : Tail logs from WAF and Juice Shop"
	@echo "  make test-unit     : Run pytest suite with coverage"
	@echo "  make lint          : Run ruff linter"
	@echo "  make test-baseline : Run controlled test suite against baseline direct endpoint"
	@echo "  make test-waf      : Run controlled test suite against WAF inspected endpoint"
	@echo "  make analyze       : Compute confusion matrix, detection, blocking rates, and latency"
	@echo "  make charts        : Generate PNG charts and figures for thesis"
	@echo "  make experiment-matrix : Run WAF suite at Paranoia Level 1-4 and compare trade-offs"
	@echo "  make experiment-holdout: Run hold-out benign set against PL1, PL2, PL2 tuned"
	@echo "  make experiment-tuned  : Run WAF suite at PL2 with narrow CRS exclusions (lab/tuning)"
	@echo "  make zap           : Run OWASP ZAP passive baseline scan"
	@echo "  make prod-up|prod-down|prod-restart|prod-logs|prod-fp : Production profile (docs/PRODUCTION.md)"

up:
	docker compose up -d juice-shop waf

down:
	docker compose down

ps:
	docker compose ps

logs:
	docker compose logs --tail=100 waf juice-shop

test-unit:
	$(PY) -m pytest -v --cov=simulator --cov=evaluation --cov-report=term-missing

lint:
	$(PY) -m ruff check .

check: lint test-unit

test-baseline:
	$(PY) simulator/run_tests.py --target http://127.0.0.1:3001 --mode baseline --repeat $(REPEAT)

test-waf:
	$(PY) simulator/run_tests.py --target http://127.0.0.1:8080 --mode waf --repeat $(REPEAT)

analyze:
	$(PY) evaluation/analyze_results.py

charts:
	$(PY) evaluation/generate_charts.py

zap:
	docker compose --profile scan run --rm zap-baseline

# Paranoia Level matrix: recreate the WAF per level, run the suite, then compare.
.PHONY: experiment-matrix
experiment-matrix:
	@for pl in 1 2 3 4; do \
	  echo "=== Paranoia Level $$pl ==="; \
	  PARANOIA=$$pl docker compose up -d --wait --force-recreate waf || exit 1; \
	  PARANOIA=$$pl $(PY) simulator/run_tests.py --target http://127.0.0.1:8080 --mode waf --repeat $(REPEAT) \
	    --output results/paranoia/pl$$pl/waf.csv || exit 1; \
	  $(PY) evaluation/analyze_results.py --waf results/paranoia/pl$$pl/waf.csv \
	    --baseline results/baseline.csv --output results/paranoia/pl$$pl/summary_metrics.json || exit 1; \
	done
	docker compose up -d --wait --force-recreate waf
	$(PY) evaluation/compare_paranoia.py

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

# PL2 with narrow exclusions (lab/tuning/), compared against the untuned matrix.
TUNED = docker compose -f docker-compose.yml -f docker-compose.tuned.yml
.PHONY: experiment-tuned
experiment-tuned:
	PARANOIA=2 $(TUNED) up -d --wait --force-recreate waf
	PARANOIA=2 TUNED=1 $(PY) simulator/run_tests.py --target http://127.0.0.1:8080 --mode waf --repeat $(REPEAT) \
	  --output results/paranoia/pl2-tuned/waf.csv
	$(PY) evaluation/analyze_results.py --waf results/paranoia/pl2-tuned/waf.csv \
	  --baseline results/baseline.csv --output results/paranoia/pl2-tuned/summary_metrics.json
	docker compose up -d --wait --force-recreate waf
	$(PY) evaluation/compare_paranoia.py

# Hold-out benign set (never used for tuning) against PL1, PL2 and PL2 tuned.
.PHONY: experiment-holdout
experiment-holdout:
	@for sc in pl1 pl2 pl2-tuned; do \
	  echo "=== Hold-out: $$sc ==="; \
	  case $$sc in \
	    pl1) docker compose up -d --wait --force-recreate waf || exit 1; pl=1; t=0;; \
	    pl2) PARANOIA=2 docker compose up -d --wait --force-recreate waf || exit 1; pl=2; t=0;; \
	    pl2-tuned) PARANOIA=2 $(TUNED) up -d --wait --force-recreate waf || exit 1; pl=2; t=1;; \
	  esac; \
	  PARANOIA=$$pl TUNED=$$t $(PY) simulator/run_tests.py --target http://127.0.0.1:8080 --mode waf \
	    --repeat $(REPEAT) --cases simulator/holdout_benign.json --output results/holdout/$$sc/waf.csv || exit 1; \
	  $(PY) evaluation/analyze_results.py --waf results/holdout/$$sc/waf.csv --baseline /dev/null \
	    --output results/holdout/$$sc/summary_metrics.json | grep -E "FP\\]|False Positive Rate|false_positive_rate" ; \
	done
	docker compose up -d --wait --force-recreate waf
