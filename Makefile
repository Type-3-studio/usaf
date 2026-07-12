.PHONY: install install-dev lint typecheck test test-cov clean pre-commit test-lab test-lab-list test-lab-validate

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

# Phase 7a: Validation Lab
test-lab-list:
	cd test_lab && python3 run.py list

test-lab-provision:
	cd test_lab && python3 run.py provision $(SCENARIO)

test-lab-validate:
	cd test_lab && python3 run.py validate $(SCENARIO)

test-lab-run:
	cd test_lab && python3 run.py run $(SCENARIO)

test-lab-destroy:
	cd test_lab && python3 run.py destroy $(SCENARIO)

test-lab-run-all:
	cd test_lab && python3 run.py run-all

all: lint format-check typecheck test
