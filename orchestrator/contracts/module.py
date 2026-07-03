"""The detection-module contract (MODULE_CONTRACT.md §2).

One interface with a capabilities descriptor so the host knows which methods a
given module actually implements: static modules don't implement on_event,
dispatch modules don't implement scan_static. The host dispatches by capability.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Flag, auto
from typing import Iterable, Protocol, runtime_checkable

from .events import Event
from .indicator import Indicator
from .process import ProcessModel
from .sample import Sample


class ModuleCaps(Flag):
    STATIC = auto()      # implements scan_static()
    BEHAVIORAL = auto()  # implements on_event()
    DISPATCH = auto()    # implements dispatch()/collect()


@dataclass
class ModuleConfig:
    data_dir: str  # rule files, model files, vendor data
    profile: str | None = None  # detonation profile for dispatch modules
    options: dict = field(default_factory=dict)  # module-specific knobs


@runtime_checkable
class DetectionModule(Protocol):
    """A detection tier. Only the methods matching `capabilities()` are called.

    Lifecycle: initialize(cfg) -> [per-run work] -> drain_indicators() -> shutdown().
    """

    def name(self) -> str: ...
    def version(self) -> str: ...
    def capabilities(self) -> ModuleCaps: ...

    def initialize(self, cfg: ModuleConfig) -> None: ...
    def shutdown(self) -> None: ...

    # STATIC: one-shot analysis of the sample bytes.
    def scan_static(self, sample: Sample) -> Iterable[Indicator]: ...

    # BEHAVIORAL / emulation: fed the uniform event stream in order, with a live
    # view of the process model. Accumulate state, emit via drain_indicators().
    def on_event(self, event: Event, model: ProcessModel) -> None: ...

    # DISPATCH: run the sample in the detonation env, then collect. Implemented
    # over the orchestrator<->detonation seam (ARCHITECTURE.md §8).
    def dispatch(self, sample: Sample, profile: str) -> str: ...  # -> run_id
    def collect(self, run_id: str) -> Iterable[Indicator]: ...

    # All modules: drain everything accumulated this run.
    def drain_indicators(self) -> list[Indicator]: ...


class BaseModule:
    """Optional convenience base: safe no-op defaults for the methods a module's
    capabilities exclude, plus an indicator buffer with drain semantics. Modules
    may implement the Protocol directly instead; this just removes boilerplate.
    """

    def __init__(self) -> None:
        self._indicators: list[Indicator] = []

    def name(self) -> str:  # pragma: no cover - overridden
        raise NotImplementedError

    def version(self) -> str:
        return "0"

    def capabilities(self) -> ModuleCaps:  # pragma: no cover - overridden
        raise NotImplementedError

    def initialize(self, cfg: ModuleConfig) -> None:
        return None

    def shutdown(self) -> None:
        return None

    def scan_static(self, sample: Sample) -> Iterable[Indicator]:
        return []

    def on_event(self, event: Event, model: ProcessModel) -> None:
        return None

    def dispatch(self, sample: Sample, profile: str) -> str:
        raise NotImplementedError(f"{self.name()} is not a dispatch module")

    def collect(self, run_id: str) -> Iterable[Indicator]:
        return []

    def emit(self, indicator: Indicator) -> None:
        self._indicators.append(indicator)

    def drain_indicators(self) -> list[Indicator]:
        out, self._indicators = self._indicators, []
        return out
