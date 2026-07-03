"""Put the repo root on sys.path so `orchestrator`, `modules`, and `sensors`
import in a fresh checkout without an editable install."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
