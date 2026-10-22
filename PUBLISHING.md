# Publishing siglint to PyPI

siglint publishes via **PyPI Trusted Publishing** (OIDC). No API token is ever
created, pasted, or stored — PyPI trusts a specific GitHub workflow directly.

## One-time setup

1. **Make the repo public** (Trusted Publishing needs a public repo).

2. **Register the publisher on PyPI** — https://pypi.org/manage/account/publishing/
   Add a *pending* publisher with:
   - **PyPI Project Name:** `siglint`
   - **Owner:** `a0merr`
   - **Repository name:** `siglint`
   - **Workflow name:** `publish.yml`
   - **Environment name:** `pypi`

   (Do the same on https://test.pypi.org first if you want a dry run.)

3. **Create the GitHub environment** — repo → Settings → Environments → New
   environment → name it `pypi`. No secrets needed.

## Cut a release

1. Bump `version` in `pyproject.toml` (and tag to match).
2. Tag and push:
   ```bash
   git tag v0.3.0
   git push origin v0.3.0
   ```
3. GitHub → Releases → **Draft a new release** → pick the tag → Publish.

Publishing the Release triggers `.github/workflows/publish.yml`, which builds
the sdist + wheel and uploads them to PyPI. Within a minute:

```bash
pip install siglint
```

## Notes

- Re-releasing the **same version** fails — PyPI versions are immutable. Bump first.
- Verify a build locally before releasing:
  ```bash
  python -m build && python -m twine check dist/*
  ```
