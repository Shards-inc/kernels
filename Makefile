PYTHON ?= python3
PIP ?= $(PYTHON) -m pip

.PHONY: install install-dev lint format typecheck test test-cov security ci clean

install:
	$(PIP) install -e .

install-dev:
	$(PIP) install -e .
	$(PIP) install pytest pytest-cov ruff mypy bandit pre-commit

lint:
	ruff check .

format:
	ruff format .

typecheck:
	mypy kernels

test:
	pytest

test-cov:
	pytest --cov=kernels --cov-report=term-missing --cov-fail-under=80

security:
	bandit -r kernels -q

ci: lint typecheck security test-cov

clean:
	rm -rf .mypy_cache .pytest_cache .ruff_cache .coverage htmlcov dist build *.egg-info
