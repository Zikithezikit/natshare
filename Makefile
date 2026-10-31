PYTHON ?= python3
VENV   ?= .venv
VPY     = $(VENV)/bin/python
# Extra pip flags, e.g. PIP_FLAGS=--break-system-packages on PEP 668 systems
PIP_FLAGS ?=

.DEFAULT_GOAL := help
.PHONY: help deps install uninstall install-dev test lint format typecheck check build clean

help: ## Show this help
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

deps: ## Install system programs (dnsmasq, hostapd, iproute2, rfkill)
	./scripts/install-deps.sh

install: deps ## Install natshare and its system dependencies (set PIP_FLAGS if pip refuses)
	$(PYTHON) -m pip install $(PIP_FLAGS) .

uninstall: ## Uninstall natshare
	$(PYTHON) -m pip uninstall $(PIP_FLAGS) -y natshare

$(VENV)/.stamp: pyproject.toml
	$(PYTHON) -m venv $(VENV)
	$(VPY) -m pip install -e '.[dev]'
	touch $@

install-dev: $(VENV)/.stamp ## Create .venv with editable install and dev tools

test: install-dev ## Run the unit tests
	$(VPY) -m pytest -q

lint: install-dev ## Lint and check formatting (ruff)
	$(VPY) -m ruff check .
	$(VPY) -m ruff format --check .

format: install-dev ## Auto-format and fix lint issues
	$(VPY) -m ruff check --fix .
	$(VPY) -m ruff format .

typecheck: install-dev ## Static type check (mypy)
	$(VPY) -m mypy natshare

check: lint typecheck test ## Run lint, typecheck and tests

build: install-dev ## Build sdist and wheel into dist/
	$(VPY) -m build

clean: ## Remove build artefacts and caches
	rm -rf build dist *.egg-info .mypy_cache .ruff_cache .pytest_cache $(VENV)
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
