"""Real-agent dispatch tier (MODULE_CONTRACT.md §1/§2/§7, ROADMAP.md Phase 2).

Dispatch modules detonate a sample in a profile whose guest runs a real security
agent, then collect that agent's own alerts and translate them into Indicators.
Wazuh is the first (ROADMAP Phase 2 "first real-agent proof").
"""

from .wazuh import (
    LiveWazuhBackend,
    WazuhAlert,
    WazuhBackend,
    WazuhModule,
    alert_to_severity,
)

__all__ = [
    "WazuhModule",
    "WazuhBackend",
    "LiveWazuhBackend",
    "WazuhAlert",
    "alert_to_severity",
]
