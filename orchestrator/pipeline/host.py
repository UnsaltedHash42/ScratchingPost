"""Module host + single-threaded event pipeline (MODULE_CONTRACT.md §2, §6).

Mirrors heavener's EventPipeline ordering guarantee: one worker thread drains a
FIFO queue, so every behavioral module sees events in the same order. Detection
logic depends on ordering (exec -> file-write -> dylib-load reads differently
shuffled), and a single consumer is the cheapest way to guarantee it.

The host owns the ProcessModel and updates it from each event *before* dispatch,
so a module's on_event() always sees a model consistent with the event it's
handling. Model maintenance here is bookkeeping (tree shape, code identity,
loaded dylibs, task-port acquisition); interpretation is the modules' job.
"""

from __future__ import annotations

import queue
import threading
from typing import Sequence

from ..contracts.events import Event, EventType
from ..contracts.indicator import Indicator
from ..contracts.module import DetectionModule, ModuleCaps
from ..contracts.process import ProcessInfo, ProcessModel

_SENTINEL = object()


class ModuleHost:
    """Feeds ordered events to the behavioral modules and collects indicators.

    Use as a context manager, or call start()/submit()/stop() explicitly. Only
    modules whose capabilities include BEHAVIORAL receive on_event().
    """

    def __init__(self, modules: Sequence[DetectionModule]) -> None:
        self.modules = list(modules)
        self._behavioral = [
            m for m in self.modules if m.capabilities() & ModuleCaps.BEHAVIORAL
        ]
        self.model = ProcessModel()
        self._q: "queue.Queue[object]" = queue.Queue()
        self._worker: threading.Thread | None = None
        self._error: BaseException | None = None

    # -- lifecycle -----------------------------------------------------------
    def start(self) -> None:
        if self._worker is not None:
            raise RuntimeError("host already started")
        self._worker = threading.Thread(target=self._run, name="sp-pipeline", daemon=True)
        self._worker.start()

    def submit(self, event: Event) -> None:
        self._q.put(event)

    def stop(self) -> None:
        """Signal end-of-stream and join the worker. Re-raises a worker error."""
        if self._worker is None:
            return
        self._q.put(_SENTINEL)
        self._worker.join()
        self._worker = None
        if self._error is not None:
            err, self._error = self._error, None
            raise err

    def __enter__(self) -> "ModuleHost":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    # -- worker --------------------------------------------------------------
    def _run(self) -> None:
        while True:
            item = self._q.get()
            if item is _SENTINEL:
                return
            event: Event = item  # type: ignore[assignment]
            try:
                self._update_model(event)
                for m in self._behavioral:
                    m.on_event(event, self.model)
            except BaseException as exc:  # surface to stop(); stop draining
                self._error = exc
                return

    # -- indicators ----------------------------------------------------------
    def collect_indicators(self) -> list[Indicator]:
        """Drain every module (behavioral and otherwise) after the stream ends."""
        out: list[Indicator] = []
        for m in self.modules:
            out.extend(m.drain_indicators())
        return out

    # -- process-model maintenance ------------------------------------------
    def _update_model(self, event: Event) -> None:
        et = event.event_type
        if et == EventType.EXEC:
            proc = event.process or ProcessInfo(pid=event.pid, ppid=event.ppid or -1, path="")
            # Recorder may omit ppid on the ProcessInfo; fall back to the header.
            if proc.ppid < 0 and event.ppid is not None:
                proc.ppid = event.ppid
            self.model.insert(proc, event.seq)
        elif et == EventType.FORK:
            child_pid = int(event.payload.get("child_pid", event.pid))
            child = event.process or ProcessInfo(pid=child_pid, ppid=event.pid, path="")
            child.pid = child_pid
            if child.ppid < 0:
                child.ppid = event.pid
            self.model.insert(child, event.seq)
        elif et == EventType.EXIT:
            self.model.mark_exit(event.pid)
        elif et in (EventType.DYLIB_LOAD, EventType.MMAP):
            path = event.payload.get("path") or event.payload.get("dylib")
            if path:
                proc = self.model.get(event.pid)
                if proc is not None and path not in proc.loaded_dylibs:
                    proc.loaded_dylibs.append(path)
        elif et == EventType.GET_TASK:
            target = event.payload.get("target_pid")
            if target is not None:
                victim = self.model.get(int(target))
                if victim is not None:
                    victim.task_port_opened_by = event.pid
