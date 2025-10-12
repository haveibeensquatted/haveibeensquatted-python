# Have I Been Squatted – Examples

These examples can be run standalone using `uv` with their own lockfile.

## Setup

```bash
cd examples
uv sync
```

This installs the examples' dependencies, including the local SDK via a path source mapping.

## Running

Set your API key and run any script with `uv`:

```bash
export HIBS_API_KEY="ak_your_api_key"

# Squat analysis
uv run python lookup.py example.com
uv run python lookup.py --log-level DEBUG example.com

# NXDOMAIN analysis
uv run python nxdomain.py example.com
uv run python nxdomain.py --log-level INFO example.com

# Comprehensive analysis
uv run python analyze.py example.com
uv run python analyze.py --log-level WARNING example.com

# Certificate Transparency search
uv run python ct_search.py --pattern "example" --kind regex

# Usage metrics
uv run python usage.py --minutes 1440
```

Each script reads `HIBS_API_KEY` from the environment and supports `--log-level`.
