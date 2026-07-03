"""eslogger subprocess recorder (ARCHITECTURE.md §7, ROADMAP.md Phase 1).

Runs Apple's stock /usr/bin/eslogger over our event set, parses its JSONL into
the uniform Event schema, and can write a capture to JSONL for replay (§6).

The live subprocess path is guarded: importing this module and constructing a
recorder work on any host, but starting eslogger requires macOS + the binary +
root (ES clients must be privileged) and raises a clear error otherwise. All
parsing is delegated to the pure `parser` module, which is what the tests cover.
"""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
import time
from pathlib import Path
from typing import Iterator

from orchestrator.contracts.events import Event

from . import parser

ESLOGGER_PATH = "/usr/bin/eslogger"

# eslogger event-subcommand names for the Phase 1 capture set (ARCHITECTURE.md §7,
# MODULE_CONTRACT.md §6). These are eslogger's spellings, not our EventType values.
# Every name verified accepted by `eslogger --list-events` on macOS 26.5.2 (Tahoe).
# NOTE: the ptrace-attach event is spelled `trace`, not `ptrace` (which eslogger
# does not accept and would make the whole invocation fail).
DEFAULT_EVENTS: tuple[str, ...] = (
    "exec",
    "fork",
    "exit",
    "create",
    "rename",
    "unlink",
    "mmap",
    "mprotect",
    "signal",
    "trace",
    "get_task",
    "cs_invalidated",
    "btm_launch_item_add",
)


class RecorderUnavailable(RuntimeError):
    """Raised when the live eslogger path can't run on this host."""


class EsloggerRecorder:
    def __init__(
        self,
        events: "tuple[str, ...] | list[str]" = DEFAULT_EVENTS,
        eslogger_path: str = ESLOGGER_PATH,
    ) -> None:
        self.events = list(events)
        self.eslogger_path = eslogger_path

    @staticmethod
    def available(eslogger_path: str = ESLOGGER_PATH) -> bool:
        return platform.system() == "Darwin" and (
            Path(eslogger_path).exists() or shutil.which(eslogger_path) is not None
        )

    def argv(self) -> list[str]:
        return [self.eslogger_path, *self.events]

    def _ensure_available(self) -> None:
        if not self.available(self.eslogger_path):
            raise RecorderUnavailable(
                f"eslogger not runnable here (need macOS + {self.eslogger_path} + root); "
                "use the parser against a captured JSONL instead"
            )

    def stream(self) -> Iterator[Event]:
        """Yield Events live from a running eslogger. Requires root. Live path —
        not exercised by the test suite."""
        self._ensure_available()
        proc = subprocess.Popen(
            self.argv(),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                ev = parser.parse_line(line)
                if ev is not None:
                    yield ev
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:  # pragma: no cover - live only
                proc.kill()

    def record_to(
        self,
        path: str | Path,
        max_events: int | None = None,
        duration: float | None = None,
    ) -> int:
        """Stream live and write a uniform-schema JSONL capture. Returns the count
        written. Stops at `max_events` and/or after `duration` seconds. Live path."""
        deadline = (time.monotonic() + duration) if duration else None
        n = 0
        with open(path, "w", encoding="utf-8") as f:
            for ev in self.stream():
                f.write(json.dumps(ev.to_dict(), separators=(",", ":")))
                f.write("\n")
                n += 1
                if max_events is not None and n >= max_events:
                    break
                if deadline is not None and time.monotonic() >= deadline:
                    break
        return n
