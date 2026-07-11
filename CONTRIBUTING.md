# Contributing to USAF

Thank you for considering contributing to USAF! This document outlines the process.

## Getting Started

1. Fork the repo at `https://github.com/type-3-studio/usaf`
2. Clone your fork: `git clone https://github.com/<your-username>/usaf.git`
3. Install dev deps: `pip install -e ".[dev]"`
4. Create a branch: `git checkout -b feature/my-feature`

## Adding a Security Check

1. Create a file in `src/usaf/checks/<category>/`
2. Use the `@register_check` decorator
3. Implement `_run_check(self, collectors) -> list[Finding]`
4. Import in the `__init__.py`
5. Add tests in `tests/unit/checks/`
6. Document the check's purpose, threat model, and limitations

## Code Standards

- Python 3.13+
- Strict typing throughout (`mypy --strict`)
- Pydantic v2 for all data models
- No shell parsing where Python APIs exist
- Every finding needs evidence and rationale
- Follow existing patterns in similar checks/collectors

## Before Submitting

```bash
# Run all tests
pytest

# Type check
mypy src/usaf

# Lint
ruff check src/usaf

# Format check
ruff format --check src/usaf

# Full pre-commit
pre-commit run --all-files
```

## Commit Messages

Use conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `ci:`.

## Pull Request Process

1. Update STATE.md if adding/removing features
2. Ensure CI passes (lint, typecheck, tests)
3. Reference any related issues

## Need Help?

See [AGENTS.md](AGENTS.md) for the complete developer guide, or browse existing checks in `src/usaf/checks/` for patterns.
