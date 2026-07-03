"""eslogger recorder: pure JSON->Event parser + guarded subprocess wrapper."""

from .parser import parse_line, parse_message, parse_stream, process_info
from .recorder import (
    DEFAULT_EVENTS,
    EsloggerRecorder,
    RecorderUnavailable,
)

__all__ = [
    "parse_line",
    "parse_message",
    "parse_stream",
    "process_info",
    "DEFAULT_EVENTS",
    "EsloggerRecorder",
    "RecorderUnavailable",
]
