# Contributing

Thank you for your interest in contributing to the Have I Been Squatted Python SDK.

## Getting started

```bash
git clone https://github.com/haveibeensquatted/haveibeensquatted-python.git
cd haveibeensquatted-python
uv sync
make hooks
make test
```

This installs two hook types:

- **pre-commit** — runs ruff, ruff format, and pytest before each commit
- **commit-msg** — enforces Conventional Commits format on every commit message

## Development workflow

```bash
make test      # run tests
make lint      # run ruff check and format check
make typecheck # run ruff type-checking rules (TCH)
make hooks     # (re-)install pre-commit hooks
```

## Running tests

```bash
uv run pytest
uv run pytest -v
uv run pytest tests/test_client.py
```

## Code style

- Follow standard Python conventions
- Use type hints for all public APIs
- Use `ruff` for linting and formatting
- All public functions and classes must have docstrings

## Adding new features

1. Update models (`models.py`) if new data types are needed
2. Update parser (`parser.py`) for new operation types
3. Update client (`client.py`) for new methods
4. Export new public APIs from `__init__.py`
5. Add tests and update examples

## Commit messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add homoglyph permutation support
fix: handle empty FQDN in ct_search_domains
docs: add example for nxdomain
test: cover rate limit header parsing
chore: update ruff to v0.15
```

Types: `feat`, `fix`, `docs`, `test`, `chore`, `refactor`, `perf`, `ci`

Breaking changes: append `!` after the type or add `BREAKING CHANGE:` in the footer.

## Pull requests

- Keep PRs focused — one logical change per PR
- Include tests for any new behaviour
- Ensure `make lint` and `make test` pass before opening a PR
- Update `examples/` if the public API changes

## Reporting issues

Use [GitHub Issues](https://github.com/haveibeensquatted/haveibeensquatted-python/issues).
For security vulnerabilities, see [SECURITY.md](SECURITY.md).
