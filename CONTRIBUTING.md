# Contributing to USAF

## Adding a Security Check

1. Create a file in `src/usaf/checks/<category>/`
2. Use the `@register_check` decorator
3. Implement `_run_check(self, collectors) -> list[Finding]`
4. Import in the `__init__.py`
5. Add tests in `tests/unit/checks/`
6. Document the check's purpose, threat model, and limitations

## Code Standards

- Python 3.13+
- Strict typing throughout
- Pydantic v2 for all data models
- No shell parsing where Python APIs exist
- Every finding needs evidence and rationale

## Testing

```bash
pytest -v
pytest --cov=usaf
mypy src/usaf
ruff check src/usaf
```
