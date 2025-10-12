# Have I Been Squatted Python SDK - Agent Guidelines

This document codifies the structure, conventions, and best practices for the Have I Been Squatted Python SDK repository.

## Repository Structure

The repository follows a standard Python package layout:

- **`src/haveibeensquatted/`** - Main package source code
  - Core modules: client implementation, HTTP handling, data models, JSON parsing
  - `__init__.py` exports the public API (re-exports from other modules)
- **`tests/`** - Test suite
  - Unit tests organized by module (one test file per source module)
  - `schema/` contains JSON schema files for API response validation
  - `data.jsonl` contains test fixture data (realistic API response streams)
- **`examples/`** - Example scripts demonstrating SDK usage
  - Complete, runnable CLI tools for each major API endpoint
  - Includes README documenting example usage
- **`scripts/`** - Utility scripts for development and maintenance
  - Tools for regenerating test data, running maintenance tasks, etc.
- **Root level** - Configuration and documentation
  - `pyproject.toml` - Project configuration, dependencies, tool settings
  - `README.md` - User-facing documentation
  - `AGENTS.md` - This file (developer guidelines)

## Type Safety

### Type Hints

- **Always use type hints** for all function parameters, return types, and class attributes
- Use `from __future__ import annotations` at the top of files to enable forward references
- Prefer `X | Y` syntax over `Union[X, Y]` for Python 3.11+
- Use `collections.abc` types (`Mapping`, `AsyncIterator`, etc.) over `typing` equivalents

### Type Checking Tools

- Use `ruff` with `TCH` rules enabled for type checking imports
- All public APIs must have complete type annotations

### Type Safety Patterns

```python
from __future__ import annotations
from collections.abc import AsyncIterator, Mapping
from typing import Protocol, runtime_checkable

# Use protocols for interfaces
@runtime_checkable
class HttpClient(Protocol):
    async def stream_get(self, url: str, headers: dict[str, str]) -> AsyncIterator[bytes]:
        ...

# Use dataclasses for data models
@dataclass
class GeoIpData:
    ip: str
    asn: GeoIpAsn | None = None
    country: GeoIpCountry | None = None

# Use enums for fixed sets of values
class Operation(Enum):
    DNS = "Dns"
    GEO_IP = "GeoIp"
    # ...
```

### Optional Fields

- Use `| None` for optional fields, not `Optional[X]`
- Always provide default values (`= None`) for optional dataclass fields
- Check for `None` before accessing optional attributes in examples and documentation

## Testing

### Test Organization

- **One test file per module**: `test_client.py` for `client.py`, `test_parser.py` for `parser.py`, etc.
- **Group related tests** in classes: `TestClient`, `TestModels`, `TestParser`
- **Use descriptive test names**: `test_squat_raises_error_on_empty_domain()` not `test_squat()`

### Test Patterns

#### Unit Tests

```python
import pytest
from haveibeensquatted import HaveIBeenSquatted, HTTPError

class TestClient:
    @pytest.mark.asyncio
    async def test_squat_raises_error_on_empty_domain(self):
        client = HaveIBeenSquatted("ak_test")
        with pytest.raises(ValueError):
            async for _ in client.squat(""):
                pass
```

#### Mock HTTP Clients

```python
class MockHttpClient:
    def __init__(self, responses: list[tuple[bytes, dict[str, str]]]):
        self.responses = responses
        self.calls: list[tuple[str, dict[str, str]]] = []

    async def get(self, url: str, headers: dict[str, str]) -> tuple[bytes, dict[str, str]]:
        self.calls.append((url, headers))
        return self.responses.pop(0)

    async def stream_get(self, url: str, headers: dict[str, str]):
        # Implementation
        ...
```

#### Schema Validation Tests

- Use JSON schema files in `tests/schema/` for validating API response structures
- Test that parsed models match expected schemas
- Update schemas when API models change

### Test Coverage

- **Aim for high coverage** of core functionality (client methods, parser logic, models)
- **Test error paths**: empty inputs, invalid data, network errors, rate limits
- **Test edge cases**: optional fields, None values, empty lists, boundary conditions
- **Test async behavior**: ensure proper async/await usage, stream handling

### Test Data

- Use `tests/data.jsonl` for realistic API response streams
- Regenerate test data using `scripts/regenerate_test_data.py` when API changes
- Keep test data minimal but representative (don't commit huge files)

### Running Tests

```bash
# Run all tests
uv run pytest

# Run specific test file
uv run pytest tests/test_client.py

# Run with coverage
uv run pytest --cov=src/haveibeensquatted

# Run with verbose output
uv run pytest -v
```

## Code Organization

### Module Responsibilities

- **`client.py`**: Main API client, method implementations, URL construction
- **`models.py`**: All dataclasses, enums, type definitions
- **`parser.py`**: JSON parsing logic, stream message parsing, data transformation
- **`http.py`**: HTTP client protocol, default implementation, error handling
- **`__init__.py`**: Public API exports only (re-exports from other modules)

### Import Organization

1. Standard library imports
2. Third-party imports
3. Local imports (from `haveibeensquatted`)

Use `ruff` with `isort` to enforce import ordering.

### Error Handling

- **Custom exceptions**: `HTTPError`, `URLError`, `RateLimitError` in `http.py`
- **Re-raise with context**: Wrap exceptions with helpful messages
- **Preserve original exceptions**: Use `from e` when re-raising

```python
except HTTPError as e:
    raise HTTPError(f"Failed to lookup squatting for {domain}: {e}") from e
```

### Async Patterns

- **Use `async def`** for all client methods that make HTTP requests
- **Use `AsyncIterator`** for streaming endpoints
- **Use `pytest-asyncio`** with `@pytest.mark.asyncio` for async tests
- **Handle async context properly**: Use `async with` for HTTP clients that support it

## Documentation

### Docstrings

- **All public functions and classes** must have docstrings
- Use Google-style docstrings with Args, Returns, Raises, Example sections
- Include code examples in docstrings where helpful

````python
async def squat(self, domain: str) -> AsyncIterator[Message]:
    """Analyze a domain for potential squatting attempts.

    This endpoint analyzes a domain for potential squatting attempts by
    generating various permutations and checking their registration status.

    Args:
        domain: The domain to analyze for squatting

    Yields:
        Message objects containing streaming results from the API

    Raises:
        ValueError: If domain is empty or invalid
        HTTPError: If the HTTP request fails

    Example:
        ```python
        async for message in client.squat("example.com"):
            if message.op == Operation.IP_ENUMERATION:
                print(message.permutation.domain.fqdn)
        ```
    """
````

### README.md

- Keep README.md user-focused (not developer-focused)
- Include installation, quick start, API examples
- Document error handling, rate limiting, authentication
- Link to detailed API docs

### Examples

- Keep examples in `examples/` directory
- Each example should be a complete, runnable script
- Include argument parsing, error handling, logging
- Document examples in `examples/README.md`

## Development Workflow

### Code Quality

This project uses [pre-commit](https://pre-commit.com/) hooks to automatically run code quality checks before commits. The hooks run:

- **Ruff linting** (`ruff check` with auto-fix)
- **Ruff formatting** (`ruff format`)
- **Pytest** (all tests must pass)
- **Common file checks** (trailing whitespace, end-of-file, YAML/JSON/TOML validation)

#### Setting Up Pre-commit Hooks

```bash
# Install pre-commit (if not already installed)
uv add --dev pre-commit

# Install the git hooks
uv run pre-commit install

# Optionally: run hooks on all files (useful after setup)
uv run pre-commit run --all-files
```

Once installed, hooks run automatically on `git commit`. To skip hooks (not recommended), use `git commit --no-verify`.

#### Continuous Integration

All pre-commit hooks and tests are automatically validated in CI (GitHub Actions) on every push and pull request:

- **Pre-commit hooks** run on all files (`pre-commit run --all-files`)
- **Pytest** runs the full test suite
- **Multiple Python versions** tested (3.11, 3.12, 3.13)

CI must pass before PRs can be merged. See `.github/workflows/ci.yml` for the full CI configuration.

#### Manual Checks (Fallback)

If you need to run checks manually:

```bash
uv run ruff check .
uv run ruff format .
uv run pytest
```

### Adding New Features

1. **Update models** (`models.py`): Add new dataclasses/enums if needed
2. **Update parser** (`parser.py`): Add parsing logic for new data types
3. **Update client** (`client.py`): Add new methods, update URLs
4. **Update exports** (`__init__.py`): Export new public APIs
5. **Add tests**: Create/update test files with comprehensive coverage
6. **Update examples**: Add example scripts if applicable
7. **Update README**: Document new features and usage
8. **Update schema**: Update JSON schemas if API structure changes

### Commit Messages

- All commits must follow the Conventional Commits specification: https://www.conventionalcommits.org/
- Use `.agents/commands/commit-message.md` to draft a Conventional Commit message from staged changes if needed.

### Dependencies

- **Minimal dependencies**: Only add dependencies when absolutely necessary
- **Use `uv`** for dependency management
- **Pin versions** in `uv.lock` (auto-generated)
- **Document dependencies** in `pyproject.toml` with version constraints

## API Design Principles

### Consistency

- **Naming**: Use consistent naming patterns across methods (`squat`, `nxdomain`, `analyze`)
- **Parameters**: Use consistent parameter names and types
- **Error handling**: Use consistent error types and messages

### Streaming vs Non-Streaming

- **Streaming endpoints**: Use `AsyncIterator[Message]` for endpoints that stream JSONL
- **Non-streaming endpoints**: Use direct return types (`CTSearchResponse`, `UsageResponse`)
- **Clear distinction**: Make it obvious which endpoints stream vs return immediately

### Protocol-Based Design

- **Use protocols** for extensibility (e.g., `HttpClient` protocol)
- **Provide default implementations** (`DefaultHttpClient`)
- **Allow customization** via dependency injection

## Common Patterns

### Domain Validation

```python
if not domain or not domain.strip():
    raise ValueError("Domain cannot be empty")
domain = domain.strip()
```

### URL Construction

```python
url = urllib.parse.urljoin(self.base_url + '/', f"lookup/squat/{domain}")
```

### JSON Parsing

```python
try:
    data = json.loads(decoded)
except json.JSONDecodeError as e:
    raise HTTPError(f"Failed to parse JSON response from {url}") from e
```

### Optional Field Handling

```python
country = message.data.country.iso_code if message.data.country else None
```

## Best Practices

1. **Type safety first**: Always add type hints, use strict typing
2. **Test thoroughly**: Write tests for happy paths, error paths, and edge cases
3. **Document clearly**: Write clear docstrings and examples
4. **Keep it simple**: Avoid over-engineering, prefer simple solutions
5. **Follow conventions**: Use existing patterns, maintain consistency
6. **Handle errors gracefully**: Provide helpful error messages, preserve context
7. **Keep dependencies minimal**: Only add dependencies when necessary
8. **Maintain backwards compatibility**: Avoid breaking changes in patch/minor versions
