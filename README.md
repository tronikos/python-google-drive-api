# python-google-drive-api

A python client library for Google Drive API.

## Background

This is a thin wrapper around the API used for a very lightweight abstraction.
The primary use case is for Home Assistant.

Based on <https://github.com/allenporter/python-google-photos-library-api>

## Development environment

```sh
python3 -m venv .venv
source .venv/bin/activate
# for Windows CMD:
# .venv\Scripts\activate.bat
# for Windows PowerShell:
# .venv\Scripts\Activate.ps1

# Install dependencies
python -m pip install --upgrade pip
python -m pip install -e .

# Run pre-commit
python -m pip install pre-commit
pre-commit install
pre-commit run --all-files

# Run tests
python -m pip install -e ".[test]"
pytest

# Build package
python -m pip install build
python -m build
```
