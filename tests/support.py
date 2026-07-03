"""Test-only helpers. Includes a trivial behavioral module used to exercise the
pipeline and replay harness without shipping real detection depth (that is later
phases). It emits one deterministic indicator per EXEC."""

from __future__ import annotations

from typing import Iterable

from orchestrator.contracts.events import Event, EventType
from orchestrator.contracts.indicator import Indicator, Severity, Tier, indicator_id
from orchestrator.contracts.module import BaseModule, ModuleCaps
from orchestrator.contracts.process import ProcessModel

_MODULE = "test.exec_watch"


class ExecWatchModule(BaseModule):
    """Behavioral module: flags every EXEC whose argv/env shows DYLD injection,
    and records the order events arrived for ordering assertions."""

    def __init__(self) -> None:
        super().__init__()
        self.seen_order: list[int] = []

    def name(self) -> str:
        return _MODULE

    def version(self) -> str:
        return "0"

    def capabilities(self) -> ModuleCaps:
        return ModuleCaps.BEHAVIORAL

    def on_event(self, event: Event, model: ProcessModel) -> None:
        self.seen_order.append(event.seq)
        if event.event_type != EventType.EXEC:
            return
        proc = model.get(event.pid)
        path = proc.path if proc else event.payload.get("target_path", "")
        has_dyld = bool(proc and any(k.startswith("DYLD_") for k in proc.env))
        self.emit(
            Indicator(
                # stable key: module + path + injection flag; deterministic -> idempotent
                id=indicator_id(_MODULE, "exec", path, has_dyld),
                name="exec-observed",
                severity=Severity.MEDIUM if has_dyld else Severity.INFO,
                tier=Tier.BEHAVIORAL,
                module=_MODULE,
                attack=["T1574.006"] if has_dyld else [],
                description=("DYLD injection env on exec" if has_dyld else "process exec"),
                evidence={"path": path, "dyld_injection": has_dyld},
            )
        )

    def drain_indicators(self) -> Iterable[Indicator]:  # type: ignore[override]
        out, self._indicators = self._indicators, []
        return list(out)
