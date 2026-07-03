"""Uniform macOS event schema (MODULE_CONTRACT.md §3).

The macOS equivalent of heavener's BehavioralEvent, derived from the ESF taxonomy.
A typed header (event type, ordering, acting process) plus an event-specific
payload dict. Recorders (eslogger wrapper now, custom sysext later) emit this;
behavioral/emulation modules consume it in order.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .process import ProcessInfo


class EventType(str, Enum):
    """The ScratchingPost event taxonomy mapped from ESF (MODULE_CONTRACT.md §3).

    Values are stable strings so JSONL captures survive enum reordering.
    """

    EXEC = "exec"                      # ES_EVENT_TYPE_NOTIFY_EXEC
    FORK = "fork"                      # NOTIFY_FORK
    EXIT = "exit"                      # NOTIFY_EXIT
    FILE_CREATE = "file_create"        # NOTIFY_CREATE
    FILE_WRITE = "file_write"          # NOTIFY_WRITE
    FILE_RENAME = "file_rename"        # NOTIFY_RENAME
    FILE_UNLINK = "file_unlink"        # NOTIFY_UNLINK
    MMAP = "mmap"                      # NOTIFY_MMAP
    MPROTECT = "mprotect"              # NOTIFY_MPROTECT
    SIGNAL = "signal"                  # NOTIFY_SIGNAL
    PTRACE = "ptrace"                  # NOTIFY_PTRACE
    GET_TASK = "get_task"              # NOTIFY_GET_TASK (+ variants)
    CS_INVALIDATED = "cs_invalidated"  # NOTIFY_CS_INVALIDATED
    BTM_LAUNCH_ITEM_ADD = "btm_launch_item_add"  # NOTIFY_BTM_LAUNCH_ITEM_ADD (persistence)
    XPROTECT = "xprotect"              # NOTIFY_XP_MALWARE_DETECTED / _REMEDIATED
    TCC_MODIFY = "tcc_modify"          # ESF AUTH events (custom sysext, not eslogger)
    SCRIPT_EXEC = "script_exec"        # synthesized: interpreter EXEC + arg capture (AMSI-gap)
    DYLIB_LOAD = "dylib_load"          # derived from MMAP / image events


# ESF event-name -> EventType. Recorders normalize the ESF kind (the single key
# under an eslogger `event` object) through this map. Event-name spellings
# confirmed against `eslogger --list-events` on macOS 26.5.2 (Tahoe): note the
# ptrace-attach event is spelled `trace` (ES_EVENT_TYPE_NOTIFY_TRACE), not `ptrace`.
ESF_NAME_TO_EVENT: dict[str, EventType] = {
    "exec": EventType.EXEC,
    "fork": EventType.FORK,
    "exit": EventType.EXIT,
    "create": EventType.FILE_CREATE,
    "write": EventType.FILE_WRITE,
    "rename": EventType.FILE_RENAME,
    "unlink": EventType.FILE_UNLINK,
    "mmap": EventType.MMAP,
    "mprotect": EventType.MPROTECT,
    "signal": EventType.SIGNAL,
    "trace": EventType.PTRACE,
    "get_task": EventType.GET_TASK,
    "get_task_read": EventType.GET_TASK,
    "get_task_inspect": EventType.GET_TASK,
    "get_task_name": EventType.GET_TASK,
    "cs_invalidated": EventType.CS_INVALIDATED,
    "btm_launch_item_add": EventType.BTM_LAUNCH_ITEM_ADD,
    "xp_malware_detected": EventType.XPROTECT,
    "xp_malware_remediated": EventType.XPROTECT,
}


@dataclass
class Event:
    """One normalized ESF-derived event.

    `seq` is a monotonic ordering key within a capture; the pipeline delivers in
    ascending `seq`. `process` is the acting process snapshot when the recorder
    supplies identity; `payload` holds event-specific fields (argv, paths,
    protections, etc.). `raw` preserves the original recorder JSON for provenance.
    """

    event_type: EventType
    seq: int
    time: float  # best-effort epoch seconds
    pid: int
    ppid: int | None = None
    process: ProcessInfo | None = None
    payload: dict = field(default_factory=dict)
    raw: dict | None = None

    def to_dict(self) -> dict:
        return {
            "event_type": self.event_type.value,
            "seq": self.seq,
            "time": self.time,
            "pid": self.pid,
            "ppid": self.ppid,
            "process": self.process.to_dict() if self.process else None,
            "payload": self.payload,
            "raw": self.raw,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Event":
        proc = d.get("process")
        return cls(
            event_type=EventType(d["event_type"]),
            seq=int(d["seq"]),
            time=float(d.get("time", 0.0)),
            pid=int(d["pid"]),
            ppid=d.get("ppid"),
            process=ProcessInfo.from_dict(proc) if proc else None,
            payload=d.get("payload", {}),
            raw=d.get("raw"),
        )
