.PHONY: up down ps logs test-baseline test-waf analyze charts test-unit lint zap help check
.DEFAULT_GOAL := help

REPEAT ?= 3
# Dataset and output directory. Defaults reproduce the original 70-case study; the extended
# dataset is run with `make experiment-extended` (or CASES=... OUT=... on any target).
CASES ?= simulator/attack_cases.json
OUT ?= results
HOLDOUT ?= simulator/holdout_benign.json
HOLDOUT_OUT ?= results/holdout
EXT_CASES := simulator/attack_cases_extended.json
EXT_OUT := results/extended
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
	@echo "  make experiment-extended: Baseline, PL1-4, PL2 tuned and hold-out on the extended dataset -> results/extended"
	@echo "  make experiment-latency: ROUNDS (default 5) order-alternated baseline/WAF PL1 runs -> <OUT>/latency"
	@echo "  make compose-check : Validate Docker Compose files"
	@echo "  Variables: CASES=<dataset.json> OUT=<results dir> REPEAT=<n> (default: original dataset, results/)"
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
	$(PY) simulator/run_tests.py --target http://127.0.0.1:3001 --mode baseline --repeat $(REPEAT) \
	  --cases $(CASES) --output $(OUT)/baseline.csv

test-waf:
	$(PY) simulator/run_tests.py --target http://127.0.0.1:8080 --mode waf --repeat $(REPEAT) \
	  --cases $(CASES) --output $(OUT)/waf.csv

analyze:
	$(PY) evaluation/analyze_results.py --waf $(OUT)/waf.csv --baseline $(OUT)/baseline.csv \
	  --output $(OUT)/summary_metrics.json

charts:
	$(PY) evaluation/generate_charts.py --summary $(OUT)/summary_metrics.json --output-dir $(OUT)

.PHONY: compose-check
compose-check:
	docker compose -f docker-compose.yml config -q
	docker compose -f docker-compose.yml -f docker-compose.tuned.yml config -q

zap:
	docker compose --profile scan run --rm zap-baseline

# Paranoia Level matrix: recreate the WAF per level, run the suite, then compare.
.PHONY: experiment-matrix
experiment-matrix:
	@for pl in 1 2 3 4; do \
	  echo "=== Paranoia Level $$pl ==="; \
	  PARANOIA=$$pl docker compose up -d --wait --force-recreate waf || exit 1; \
	  PARANOIA=$$pl $(PY) simulator/run_tests.py --target http://127.0.0.1:8080 --mode waf --repeat $(REPEAT) \
	    --cases $(CASES) --output $(OUT)/paranoia/pl$$pl/waf.csv || exit 1; \
	  $(PY) evaluation/analyze_results.py --waf $(OUT)/paranoia/pl$$pl/waf.csv \
	    --baseline $(OUT)/baseline.csv --output $(OUT)/paranoia/pl$$pl/summary_metrics.json || exit 1; \
	done
	docker compose up -d --wait --force-recreate waf
	$(PY) evaluation/compare_paranoia.py --matrix-dir $(OUT)/paranoia

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
	  --cases $(CASES) --output $(OUT)/paranoia/pl2-tuned/waf.csv
	$(PY) evaluation/analyze_results.py --waf $(OUT)/paranoia/pl2-tuned/waf.csv \
	  --baseline $(OUT)/baseline.csv --output $(OUT)/paranoia/pl2-tuned/summary_metrics.json
	docker compose up -d --wait --force-recreate waf
	$(PY) evaluation/compare_paranoia.py --matrix-dir $(OUT)/paranoia

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
	    --repeat $(REPEAT) --cases $(HOLDOUT) --output $(HOLDOUT_OUT)/$$sc/waf.csv || exit 1; \
	  $(PY) evaluation/analyze_results.py --waf $(HOLDOUT_OUT)/$$sc/waf.csv --baseline /dev/null \
	    --output $(HOLDOUT_OUT)/$$sc/summary_metrics.json | grep -E "FP\\]|False Positive Rate|false_positive_rate" ; \
	done
	docker compose up -d --wait --force-recreate waf

# Extended dataset (simulator/attack_cases_extended.json): fresh baseline and WAF runs into
# results/extended so they are never mixed with the original-dataset results in results/.
.PHONY: experiment-extended
experiment-extended:
	docker compose up -d --wait juice-shop waf
	$(MAKE) test-baseline test-waf analyze charts experiment-matrix experiment-tuned CASES=$(EXT_CASES) OUT=$(EXT_OUT)
	$(MAKE) experiment-holdout HOLDOUT_OUT=$(EXT_OUT)/holdout

# Latency: ROUNDS order-alternated baseline/WAF (PL1) runs, summarized across rounds. Audit-log
# correlation is disabled (--no-docker-logs) because these runs are for latency only, never for
# detection metrics; it also keeps the request pacing identical in both modes.
ROUNDS ?= 5
LAT_OUT ?= $(OUT)/latency
.PHONY: experiment-latency
experiment-latency:
	docker compose up -d --wait juice-shop waf
	@for i in $$(seq 1 $(ROUNDS)); do \
	  if [ $$((i % 2)) -eq 1 ]; then order="baseline waf"; else order="waf baseline"; fi; \
	  for m in $$order; do \
	    if [ $$m = baseline ]; then t=http://127.0.0.1:3001; else t=http://127.0.0.1:8080; fi; \
	    echo "=== Latency round $$i: $$m ==="; \
	    $(PY) simulator/run_tests.py --target $$t --mode $$m --repeat $(REPEAT) --cases $(CASES) \
	      --no-docker-logs --output $(LAT_OUT)/round$$i/$$m.csv > /dev/null || exit 1; \
	  done; \
	done
	$(PY) evaluation/latency_rounds.py --rounds-dir $(LAT_OUT)
