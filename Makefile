PYTHON ?= python3
PIP ?= $(PYTHON) -m pip

.PHONY: install install-dev lint format format-check typecheck test test-cov security dep-scan smoke build ci clean

install:
	$(PIP) install -e .

install-dev:
	$(PIP) install -e .
	$(PIP) install pytest pytest-cov ruff mypy bandit safety pip-audit build twine pre-commit

lint:
	ruff check .

format:
	ruff format .

format-check:
	ruff format --check .

typecheck:
	mypy kernels implementations

test:
	pytest

test-cov:
	@if pytest --help 2>/dev/null | grep -q -- "--cov"; then \
		pytest --cov=kernels --cov=implementations --cov-report=term-missing --cov-fail-under=80; \
	else \
		echo "pytest-cov not installed; running pytest without coverage"; \
		pytest; \
	fi

security:
	@if command -v bandit >/dev/null 2>&1; then \
		bandit -r kernels implementations -q; \
	else \
		echo "bandit not installed; skipping security scan"; \
	fi

dep-scan:
	safety check --full-report || true
	pip-audit

smoke:
	./scripts/smoke.sh

build:
	@if $(PYTHON) -c "import build" >/dev/null 2>&1; then \
		$(PYTHON) -m build; \
	else \
		echo "python-build package not installed; skipping build step"; \
	fi

twine-check:
	twine check dist/*

ci: lint format-check typecheck security test-cov smoke build

clean:
	rm -rf .mypy_cache .pytest_cache .ruff_cache .coverage htmlcov dist build *.egg-info .tmp
