.PHONY: help up down logs status install run-baseline run-attacks benchmark report clean

COMPOSE_FILE := docker/docker-compose.yml
COMPOSE := docker compose -f $(COMPOSE_FILE)

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ============================================
# Infrastructure
# ============================================

up: ## Start the lab environment
	$(COMPOSE) up -d --build
	@echo "Waiting for Elasticsearch to be ready..."
	@sleep 30
	@echo "Lab environment is ready!"
	@echo "  Elasticsearch: http://localhost:9200"
	@echo "  Kibana: http://localhost:5601"

down: ## Stop the lab environment
	$(COMPOSE) down -v

logs: ## Show logs from all containers
	$(COMPOSE) logs -f

logs-target: ## Show logs from target container
	$(COMPOSE) logs -f target

logs-elastic: ## Show logs from Elasticsearch
	$(COMPOSE) logs -f elasticsearch

status: ## Check lab environment status
	@python -m benchmark.cli status

shell: ## Open shell in target container
	docker exec -it soc-target /bin/bash

# ============================================
# Development
# ============================================

install: ## Install Python dependencies
	pip install -e ".[dev]"

lint: ## Run linters
	ruff check benchmark tests
	black --check benchmark tests

format: ## Format code
	ruff check --fix benchmark tests
	black benchmark tests

test: ## Run tests
	pytest tests/ -v

# ============================================
# Benchmark Operations
# ============================================

run-baseline: ## Run baseline workload for FP measurement
	python -m benchmark.cli run-baseline --iterations 10

run-attacks: ## Execute all attacks from manifest
	python -m benchmark.cli run-attacks --delay 2.0

benchmark: ## Run full benchmark (baseline + attacks + report)
	python -m benchmark.cli benchmark --baseline-iterations 5 --attack-delay 2.0

report: ## Generate report from latest results
	@latest=$$(ls -t results/attacks_*.json 2>/dev/null | head -1); \
	if [ -z "$$latest" ]; then \
		echo "No attack results found. Run 'make run-attacks' first."; \
		exit 1; \
	fi; \
	python -m benchmark.cli report --attacks-file "$$latest" --baseline-file results/baseline_latest.json

# ============================================
# Sigma Rules
# ============================================

compile-rules: ## Compile Sigma rules to Elasticsearch format
	@echo "Compiling Sigma rules..."
	@mkdir -p rules/elastic
	@for f in rules/sigma/*.yml; do \
		name=$$(basename "$$f" .yml); \
		sigma convert -t elasticsearch -p ecs_windows "$$f" > "rules/elastic/$$name.json" 2>/dev/null || true; \
	done
	@echo "Rules compiled to rules/elastic/"

# ============================================
# Cleanup
# ============================================

clean: ## Remove generated files
	rm -rf results/*.json results/*.md
	rm -rf rules/elastic/*.json
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

clean-all: clean down ## Remove everything including Docker volumes
	docker volume rm soc-detection-benchmark_es-data 2>/dev/null || true
	docker volume rm soc-detection-benchmark_target-logs 2>/dev/null || true
