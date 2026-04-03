.PHONY: test lint typecheck hooks

## Run all tests
test:
	uv run pytest

## Run ruff lint and format check
lint:
	uv run ruff check .
	uv run ruff format --check .

## Run type-related lint rules (TCH: type-checking imports)
typecheck:
	uv run ruff check . --select TCH

## Install pre-commit hooks (run once after cloning)
hooks:
	uv run pre-commit install --hook-type pre-commit --hook-type commit-msg
