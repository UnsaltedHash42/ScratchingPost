"""Capture / replay harness (MODULE_CONTRACT.md §6).

Decouples module development from the detonation environment: capture the ESF
stream to JSONL once, then replay it through the same single-threaded pipeline
against any set of modules, no live VM or entitlement per iteration. Indicator
IDs are deterministic FNV-1a hashes, so replaying the same capture through the
same modules is idempotent — replaying twice yields byte-identical indicators.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Iterator, Sequence

from ..contracts.events import Event
from ..contracts.indicator import Indicator
from ..contracts.module import DetectionModule
from .host import ModuleHost


def read_capture(path: str | Path) -> Iterator[Event]:
    """Yield events from a JSONL capture in file order. Blank lines are skipped."""
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield Event.from_dict(json.loads(line))


def write_capture(path: str | Path, events: Iterable[Event]) -> int:
    """Write events to a JSONL capture. Returns the count written."""
    n = 0
    with open(path, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev.to_dict(), separators=(",", ":")))
            f.write("\n")
            n += 1
    return n


def _dedup_sorted(indicators: Iterable[Indicator]) -> list[Indicator]:
    """Collapse by deterministic id and sort, so replay output is stable
    regardless of module registration order or duplicate emissions."""
    by_id: dict[str, Indicator] = {}
    for ind in indicators:
        by_id.setdefault(ind.id, ind)
    return sorted(by_id.values(), key=lambda i: i.id)


def replay_events(
    events: Iterable[Event], modules: Sequence[DetectionModule]
) -> list[Indicator]:
    """Push an event stream through the pipeline against `modules`, in `seq`
    order, and return the deduplicated, id-sorted indicators."""
    ordered = sorted(events, key=lambda e: e.seq)
    with ModuleHost(modules) as host:
        for ev in ordered:
            host.submit(ev)
    return _dedup_sorted(host.collect_indicators())


def replay_capture(
    path: str | Path, modules: Sequence[DetectionModule]
) -> list[Indicator]:
    """Load a JSONL capture and replay it. See `replay_events`."""
    return replay_events(read_capture(path), modules)
