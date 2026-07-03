"""ScratchingPost detection contracts (MODULE_CONTRACT.md).

The spine every tier hangs on: the event schema, the process model, the indicator
currency, the sample, and the module interface.
"""

from .events import ESF_NAME_TO_EVENT, Event, EventType
from .indicator import Indicator, Severity, Tier, fnv1a_64, indicator_id
from .module import BaseModule, DetectionModule, ModuleCaps, ModuleConfig
from .process import DANGEROUS_ENTITLEMENTS, ProcessInfo, ProcessModel
from .sample import Sample

__all__ = [
    "ESF_NAME_TO_EVENT",
    "Event",
    "EventType",
    "Indicator",
    "Severity",
    "Tier",
    "fnv1a_64",
    "indicator_id",
    "BaseModule",
    "DetectionModule",
    "ModuleCaps",
    "ModuleConfig",
    "DANGEROUS_ENTITLEMENTS",
    "ProcessInfo",
    "ProcessModel",
    "Sample",
]
