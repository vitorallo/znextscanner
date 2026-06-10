"""Version-string helpers shared across checks."""

from __future__ import annotations

import re


def version_tuple(v: str) -> tuple[int, ...]:
    """Turn a version string into a comparable tuple of its integer components."""
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts) if parts else (0,)


def extract_java_version(block: str) -> str | None:
    """Extract a comparable 4-part Java version from a ``java -version`` block.

    Prefers the IBM SR ``build x.y.z.b`` form, then any bare quad, then the
    ``version "..."`` string.
    """
    build = re.search(r"build (\d+\.\d+\.\d+\.\d+)", block)
    if build:
        return build.group(1)
    quad = re.search(r"\b(\d+\.\d+\.\d+\.\d+)\b", block)
    if quad:
        return quad.group(1)
    ver = re.search(r'version "?([0-9][0-9._]+)', block)
    return ver.group(1).replace("_", ".") if ver else None
