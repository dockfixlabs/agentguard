# Fix: Switch to PyPI Trusted Publishing (no token needed)

The current publish workflow uses `PYPI_API_TOKEN` which keeps failing with "File already exists" 
on retry. The fix is to switch to PyPI Trusted Publishing (OIDC), which is the recommended approach.

## Steps to set up Trusted Publishing:

1. Go to https://pypi.org/manage/account/publishing/
2. Add a new pending publisher:
   - PyPI Project Name: `dfx-agentguard`
   - Owner: `dockfixlabs`
   - Repository: `agentguard`
   - Workflow filename: `publish.yml`
   - Environment name: `pypi`
3. Once the first publish succeeds, the publisher is confirmed.

## Updated publish.yml:

```yaml
name: Publish to PyPI

on:
  workflow_dispatch:
  release:
    types: [published]

jobs:
  publish:
    runs-on: ubuntu-latest
    environment: pypi
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v6
        with:
          python-version: '3.12'
      - name: Install build tools
        run: pip install build
      - name: Build package
        run: python -m build
      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1
```

The key change: remove `password: ${{ secrets.PYPI_API_TOKEN }}` and let OIDC handle authentication.
