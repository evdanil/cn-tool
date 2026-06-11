"""Shared build-stamp reader for cn-tool and its bundled CLIs.

The repo-root ``version`` file is the single CI-managed source of truth for the
*platform* version (``MAJOR.MINOR.BUILD``) plus the short git ``BUILD_HASH``.
It is rewritten on every release by ``.github/workflows/build.yml``.

Each bundled tool (cn-lens, cn-route, cn-draw) additionally carries its own
*component* ``__version__`` and renders a combined ``--version`` line through
this module, so the per-tool version and the shared package build stamp stay
consistent and the parsing logic lives in exactly one place.

Hybrid ``--version`` format::

    cn-route 0.2.1 (cn-tool 0.2.88, build 1b5d97f)
             ^^^^^           ^^^^^^        ^^^^^^^
        component        package version   git hash
        (per tool)       (version file)    (version file)

When the ``version`` file is missing or unparseable, the platform suffix is
omitted and the component version is shown alone (never a misleading
``unknown``).
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import NamedTuple, Optional


class BuildStamp(NamedTuple):
    package_version: str  # e.g. "0.2.88"
    build_hash: str       # e.g. "1b5d97f" (may be "")


def parse_version_text(content: str) -> Optional[BuildStamp]:
    """Parse the ``KEY=value`` body of a ``version`` file.

    Returns ``None`` when the required ``MAJOR``/``MINOR`` keys are missing
    or non-numeric (a hand-edited file must not yield a stamp like
    ``"abc.2.88"``), so callers can fall back to a component-only version
    line. A non-numeric optional ``BUILD`` degrades to ``MAJOR.MINOR``.
    """
    parts: dict[str, str] = {}
    for line in content.splitlines():
        key, sep, val = line.partition("=")
        if sep:
            parts[key.strip()] = val.strip()

    major = parts.get("MAJOR", "")
    minor = parts.get("MINOR", "")
    build = parts.get("BUILD", "")
    if not (major.isdigit() and minor.isdigit()):
        return None
    if not build.isdigit():
        build = ""
    build_hash = parts.get("BUILD_HASH", "")

    package_version = f"{major}.{minor}.{build}" if build else f"{major}.{minor}"
    return BuildStamp(package_version=package_version, build_hash=build_hash)


@lru_cache(maxsize=1)
def build_stamp() -> Optional[BuildStamp]:
    """Parse the repo-root ``version`` file.

    Returns ``None`` when the file is absent or unparseable so callers can fall
    back to a component-only version line. Result is cached after first call.
    """
    try:
        version_file = Path(__file__).resolve().parent / "version"
        content = version_file.read_text(encoding="utf-8")
    except OSError:
        return None
    return parse_version_text(content)


def package_version_string() -> str:
    """Legacy combined string used by cn-tool: ``"0.2.88 hash 1b5d97f"``.

    Falls back to ``"unknown"`` when no build stamp is available. This matches
    the string the CI previously injected into ``main.py`` at build time.
    """
    stamp = build_stamp()
    if stamp is None:
        return "unknown"
    if stamp.build_hash:
        return f"{stamp.package_version} hash {stamp.build_hash}"
    return stamp.package_version


def version_line(tool_name: str, component_version: str) -> str:
    """Render a bundled tool's ``--version`` line in the hybrid format.

    Example: ``cn-route 0.2.1 (cn-tool 0.2.88, build 1b5d97f)``.
    Without a build stamp the platform suffix is dropped: ``cn-route 0.2.1``.
    """
    stamp = build_stamp()
    if stamp is None:
        return f"{tool_name} {component_version}"
    suffix = f"cn-tool {stamp.package_version}"
    if stamp.build_hash:
        suffix += f", build {stamp.build_hash}"
    return f"{tool_name} {component_version} ({suffix})"
