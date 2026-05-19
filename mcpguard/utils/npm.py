from __future__ import annotations

import httpx

_NPM_REGISTRY = "https://registry.npmjs.org"
_TIMEOUT = 8.0


def fetch_latest_version(package: str) -> str | None:
    try:
        url = f"{_NPM_REGISTRY}/{package}/latest"
        r = httpx.get(url, timeout=_TIMEOUT, follow_redirects=True)
        if r.status_code == 200:
            return r.json().get("version")
    except Exception:
        pass
    return None


def package_exists(package: str) -> bool:
    try:
        url = f"{_NPM_REGISTRY}/{package}"
        r = httpx.get(url, timeout=_TIMEOUT, follow_redirects=True)
        return r.status_code == 200
    except Exception:
        return False
