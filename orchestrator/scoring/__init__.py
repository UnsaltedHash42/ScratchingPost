"""Detection Score aggregation + report (MODULE_CONTRACT.md §5).

Adapted from LitterBox's detection-score model, credited in score.py and the README.
"""

from .report import render_json, render_report
from .score import (
    SEVERITY_WEIGHT,
    TIER_WEIGHT,
    Contribution,
    DetectionScore,
    score_indicators,
)

__all__ = [
    "score_indicators",
    "DetectionScore",
    "Contribution",
    "SEVERITY_WEIGHT",
    "TIER_WEIGHT",
    "render_report",
    "render_json",
]
