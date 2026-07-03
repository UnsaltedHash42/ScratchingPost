"""ScratchingPost orchestrator: contracts, module host + pipeline, detonation seam.

`analyze()` (conductor.py) is the Phase-1 entry point that wires the whole slice
into one call. Importing it here is safe: the conductor imports the concrete
detection modules lazily, so `import orchestrator` stays free of a
framework->plugin import at load time."""

from .conductor import AnalysisResult, analyze, default_static_modules

__all__ = ["analyze", "AnalysisResult", "default_static_modules"]
