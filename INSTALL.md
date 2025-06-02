# Installation Guide

## Installing tailops as a Python Package

With the new `pyproject.toml`, tailops can now be installed as a proper Python package.

## Local Development Installation

```bash
# Install in development mode (editable)
pip install -e .

# Now you can use the tailops command globally
tailops --help
tailops version
tailops status
```

## Building the Package

```bash
# Install build tools
pip install build twine

# Build the package
python -m build

# This creates:
# - dist/tailops-1.0.0.tar.gz (source distribution)
# - dist/tailops-1.0.0-py3-none-any.whl (wheel)
```

## Installing from Built Package

```bash
# Install from wheel
pip install dist/tailops-1.0.0-py3-none-any.whl

# Or install from source
pip install dist/tailops-1.0.0.tar.gz
```

## Publishing to PyPI (Future)

```bash
# Upload to PyPI (when ready)
twine upload dist/*

# Then users can install with:
pip install tailops
```

## Development Dependencies

```bash
# Install with development dependencies
pip install -e ".[dev]"

# This includes:
# - pytest (testing)
# - black (code formatting)
# - flake8 (linting)
# - mypy (type checking)
# - pre-commit (git hooks)
```

## Package Features

- **Entry Point**: `tailops` command available globally after installation
- **Package Data**: Config templates included automatically
- **Dependencies**: All requirements properly specified
- **Development Tools**: Configured for black, flake8, mypy, pytest
- **PyPI Ready**: Complete metadata for package distribution

## Verification

After installation, verify everything works:

```bash
tailops --version
tailops status
tailops tenant --help
tailops device --help
```

## Uninstalling

```bash
pip uninstall tailops
