# PyPI Distribution Guide for tailops

## Phase 1: TestPyPI Testing (Recommended First Step)

### 1. Create TestPyPI Account
1. Go to https://test.pypi.org/account/register/
2. Create account and verify email
3. Go to Account Settings → API tokens
4. Create a new API token with "Entire account" scope
5. Save the token (starts with `pypi-`)

### 2. Configure Twine for TestPyPI
```bash
# Create or edit ~/.pypirc
cat > ~/.pypirc << EOF
[distutils]
index-servers = 
    pypi
    testpypi

[pypi]
username = __token__
password = <your-pypi-token-here>

[testpypi]
repository = https://test.pypi.org/legacy/
username = __token__
password = <your-testpypi-token-here>
EOF

# Secure the file
chmod 600 ~/.pypirc
```

### 3. Upload to TestPyPI
```bash
# Upload current build
twine upload --repository testpypi dist/*

# Expected output:
# Uploading distributions to https://test.pypi.org/legacy/
# Uploading tailops-1.0.0-py3-none-any.whl
# Uploading tailops-1.0.0.tar.gz
```

### 4. Test Installation from TestPyPI
```bash
# Create test environment
python3 -m venv test-env
source test-env/bin/activate

# Install from TestPyPI
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ tailops

# Test the installation
tailops --version
tailops --help
tailops status

# Cleanup
deactivate
rm -rf test-env
```

## Phase 2: Production PyPI Release

### 1. Create PyPI Account
1. Go to https://pypi.org/account/register/
2. Create account and verify email
3. Go to Account Settings → API tokens
4. Create a new API token with "Entire account" scope
5. Update ~/.pypirc with the PyPI token

### 2. Upload to PyPI
```bash
# Final upload to production PyPI
twine upload dist/*

# Expected output:
# Uploading distributions to https://upload.pypi.org/legacy/
# Uploading tailops-1.0.0-py3-none-any.whl
# Uploading tailops-1.0.0.tar.gz
```

### 3. Verify Production Installation
```bash
# Anyone can now install with:
pip install tailops

# Test it works
tailops --version
```

## Version Management

### For Future Releases
1. Update version in `pyproject.toml`
2. Update `CHANGELOG.md`
3. Clean and rebuild:
   ```bash
   rm -rf dist/ build/ tailops.egg-info/
   pyproject-build
   twine check dist/*
   ```
4. Upload to TestPyPI first, then PyPI

### Semantic Versioning
- `1.0.1` - Bug fixes
- `1.1.0` - New features (backward compatible)
- `2.0.0` - Breaking changes

## Automation Options

### GitHub Actions (Future)
Create `.github/workflows/release.yml`:
```yaml
name: Release to PyPI
on:
  push:
    tags:
      - 'v*'
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    - name: Install dependencies
      run: pip install build twine
    - name: Build package
      run: python -m build
    - name: Publish to PyPI
      env:
        TWINE_USERNAME: __token__
        TWINE_PASSWORD: ${{ secrets.PYPI_API_TOKEN }}
      run: twine upload dist/*
```

## Current Status

✅ **Package Built Successfully**
- Source distribution: `tailops-1.0.0.tar.gz`
- Wheel distribution: `tailops-1.0.0-py3-none-any.whl`
- Both packages passed `twine check`

✅ **Ready for TestPyPI Upload**
- Configure TestPyPI credentials
- Upload with: `twine upload --repository testpypi dist/*`

✅ **Ready for PyPI Production**
- After TestPyPI validation
- Upload with: `twine upload dist/*`

## Next Steps

1. **Set up TestPyPI account and credentials**
2. **Upload to TestPyPI for validation**
3. **Test installation from TestPyPI**
4. **Upload to production PyPI**
5. **Update README with `pip install tailops` instructions**

Once uploaded to PyPI, users will be able to install tailops with:
```bash
pip install tailops
tailops --help
```

This completes Phase 1 of Version 1.1 features!
