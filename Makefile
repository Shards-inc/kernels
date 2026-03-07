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
	pytest --cov=kernels --cov=implementations --cov-report=term-missing --cov-fail-under=80

security:
	bandit -r kernels implementations -q

dep-scan:
	safety check --full-report || true
	pip-audit

smoke:
	./scripts/smoke.sh

build:
	$(PYTHON) -m build

twine-check:
	twine check dist/*

ci: lint format-check typecheck security test-cov smoke build

clean:
	rm -rf .mypy_cache .pytest_cache .ruff_cache .coverage htmlcov dist build *.egg-info .tmp
