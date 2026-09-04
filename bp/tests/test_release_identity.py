from __future__ import annotations

import json
import re
from pathlib import Path

import bp


ROOT = Path(__file__).resolve().parents[2]


def _pyproject_version() -> str:
    text = (ROOT / "bp" / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"', text)
    assert match, "bp/pyproject.toml declares no version"
    return match.group(1)


def _kotlin_extension_version() -> str:
    text = (ROOT / "src" / "main" / "kotlin" / "com" / "burprest" / "BuildIdentity.kt").read_text(
        encoding="utf-8"
    )
    match = re.search(r'EXTENSION_VERSION:\s*String\s*=\s*"([^"]+)"', text)
    assert match, "BuildIdentity.kt declares no EXTENSION_VERSION"
    return match.group(1)


def _gradle_version() -> str:
    text = (ROOT / "build.gradle.kts").read_text(encoding="utf-8")
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"', text)
    assert match, "build.gradle.kts declares no version"
    return match.group(1)


def _openapi_version() -> str:
    document = json.loads(
        (ROOT / "src" / "main" / "resources" / "openapi.json").read_text(encoding="utf-8")
    )
    return str(document["info"]["version"])


def test_every_published_version_is_the_same_release() -> None:
    """A deployed artifact must not be able to claim a version its behavior does not match."""
    versions = {
        "bp.__version__": bp.__version__,
        "bp/pyproject.toml": _pyproject_version(),
        "BuildIdentity.kt": _kotlin_extension_version(),
        "build.gradle.kts": _gradle_version(),
        "openapi.json": _openapi_version(),
    }
    assert len(set(versions.values())) == 1, f"release identity drifted: {versions}"


def test_release_version_is_semantic() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+", bp.__version__), bp.__version__
