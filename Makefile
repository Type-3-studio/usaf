.PHONY: install install-dev lint typecheck test test-cov clean pre-commit

install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

lint:
	ruff check src/usaf tests

lint-fix:
	ruff check --fix src/usaf tests

format:
	ruff format src/usaf tests

format-check:
	ruff format --check src/usaf tests

typecheck:
	mypy src/usaf

test:
	pytest

test-cov:
	pytest --cov=usaf --cov-report=term-missing --cov-report=html

test-v:
	pytest -v

pre-commit:
	pre-commit run --all-files

clean:
	rm -rf .pytest_cache
	rm -rf .mypy_cache
	rm -rf htmlcov
	rm -rf .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

all: lint format-check typecheck test
