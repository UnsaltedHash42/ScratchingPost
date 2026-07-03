"""Sample: the bytes under analysis (MODULE_CONTRACT.md §2).

Static modules operate on a Sample one-shot; dispatch modules detonate it. Kept
deliberately thin — identity (path, hash, size) plus a coarse type hint. Deeper
typing (Mach-O vs pkg vs dmg vs mobileconfig) is the static parser's job.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass


@dataclass
class Sample:
    path: str
    sha256: str
    size: int
    filetype: str | None = None  # coarse hint; refined by the static parser

    @classmethod
    def from_path(cls, path: str, filetype: str | None = None) -> "Sample":
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return cls(
            path=os.fspath(path),
            sha256=h.hexdigest(),
            size=os.path.getsize(path),
            filetype=filetype,
        )
