"""eslogger JSON -> uniform Event parser (MODULE_CONTRACT.md §3).

Pure and side-effect-free so it is unit-testable on any host against captured
fixture JSON — no live subprocess, no macOS required. `/usr/bin/eslogger` emits
one serialized ES message (JSON) per line; each line maps to zero or one Event.

Reconciled against a real eslogger capture on macOS 26.5.2 (Tahoe, build 25F84) on
2026-07-01: exec (`target.executable.path`, `target.audit_token.pid`, `signing_id`,
`team_id`, `cdhash` hex string, `is_platform_binary`, `codesigning_flags`,
`responsible_audit_token.pid`, `args`, `env`, `cwd.path`), fork (`child.audit_token.pid`),
and file events (unlink `target.path`; rename `source.path` + `destination.new_path`
dir+filename; create `destination.existing_file.path`). Fields we can't find degrade
to defaults rather than raising, so an unknown/renamed field never drops the event.
"""

from __future__ import annotations

import json
from typing import Any, Iterator

from orchestrator.contracts.events import ESF_NAME_TO_EVENT, Event, EventType
from orchestrator.contracts.process import ProcessInfo

# ES codesigning flag bits we key on (long-standing kernel constants). Confirmed
# against real codesigning_flags on macOS 26.5.2: a platform binary reports
# 0x26008601, which has CS_PLATFORM_BINARY set and classifies as "platform".
CS_ADHOC = 0x0000002
CS_PLATFORM_BINARY = 0x4000000


def _get(d: Any, *path: str, default: Any = None) -> Any:
    """Nested dict lookup that tolerates missing/None intermediates."""
    cur = d
    for key in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
    return default if cur is None else cur


def _pid(proc: dict) -> int:
    # pid lives inside the audit_token in ES; some renderings hoist it.
    for cand in (_get(proc, "audit_token", "pid"), proc.get("pid")):
        if isinstance(cand, int):
            return cand
    return -1


def _cdhash(proc: dict) -> str:
    v = proc.get("cdhash")
    if isinstance(v, str):
        return v
    if isinstance(v, (list, tuple)):
        try:
            return "".join(f"{int(b):02x}" for b in v)
        except (TypeError, ValueError):
            return ""
    return ""


def _signature_type(proc: dict) -> str:
    flags = int(proc.get("codesigning_flags", 0) or 0)
    if proc.get("is_platform_binary") or (flags & CS_PLATFORM_BINARY):
        return "platform"
    if flags & CS_ADHOC:
        return "adhoc"
    if proc.get("team_id"):
        return "developer_id"
    if proc.get("signing_id"):
        return "app_store"
    return "unsigned"


def _env_list_to_dict(env: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    if isinstance(env, list):
        for item in env:
            if isinstance(item, str) and "=" in item:
                k, v = item.split("=", 1)
                out[k] = v
    return out


def process_info(proc: dict, *, argv: list | None = None, env: Any = None) -> ProcessInfo:
    """Build a ProcessInfo from an ES process object (es_process_t rendering)."""
    return ProcessInfo(
        pid=_pid(proc),
        ppid=int(proc.get("ppid", -1) or -1),
        path=_get(proc, "executable", "path", default=""),
        argv=list(argv) if argv else [],
        env=_env_list_to_dict(env),
        responsible_pid=int(_get(proc, "responsible_audit_token", "pid", default=-1) or -1),
        team_id=proc.get("team_id") or None,
        signing_id=proc.get("signing_id") or None,
        cdhash=_cdhash(proc),
        is_platform_binary=bool(proc.get("is_platform_binary", False)),
        signature_type=_signature_type(proc),
        csflags=int(proc.get("codesigning_flags", 0) or 0),
    )


# -- per-event-type payload extraction ---------------------------------------
def _payload_exec(body: dict) -> tuple[dict, list, Any]:
    argv = body.get("args") or []
    env = body.get("env")
    payload = {
        "argv": list(argv),
        "cwd": _get(body, "cwd", "path"),
        "target_path": _get(body, "target", "executable", "path"),
    }
    return payload, list(argv), env


def _rename_dest(dest_block: dict) -> str | None:
    """Full destination path of a rename/create. ES gives it two ways: an
    `existing_file` (overwrite) carries a full `path`; a `new_path` (fresh name)
    carries a `dir.path` + a bare `filename` that must be joined. Reconciled
    against real macOS 26.5.2 output."""
    existing = _get(dest_block, "existing_file", "path")
    if existing:
        return existing
    np = dest_block.get("new_path") if isinstance(dest_block, dict) else None
    if isinstance(np, dict):
        directory = _get(np, "dir", "path")
        filename = np.get("filename")
        if directory and filename:
            return f"{directory.rstrip('/')}/{filename}"
        return filename or None
    return None


def _payload_file(body: dict) -> dict:
    """create/unlink carry a target file; rename carries source + destination.
    Reconciled against real macOS 26.5.2 eslogger output (see module docstring):
    unlink -> `target.path`, rename -> `source.path` + `destination.new_path`
    (dir+filename), create -> `destination.existing_file.path` or `.new_path`."""
    dest_block = body.get("destination") if isinstance(body.get("destination"), dict) else {}
    path = (
        _get(body, "target", "path")             # unlink target; create (some variants)
        or _get(body, "source", "path")          # rename source
        or _get(dest_block, "existing_file", "path")  # create over an existing file
        or _get(dest_block, "path")              # create (flattened rendering)
        or _rename_dest(dest_block)              # create with a fresh name
        or _get(body, "file", "path")
    )
    dest = _rename_dest(dest_block)
    payload: dict = {}
    if path:
        payload["path"] = path
    if dest and dest != path:  # only when it's an actual move target
        payload["dest"] = dest
    return payload


def _payload_generic(body: dict) -> dict:
    return body if isinstance(body, dict) else {}


def parse_message(msg: dict) -> Event | None:
    """Map one deserialized eslogger message to an Event, or None if its ES kind
    is one we don't model."""
    event_block = msg.get("event")
    if not isinstance(event_block, dict) or not event_block:
        return None
    esf_name = next(iter(event_block))
    et = ESF_NAME_TO_EVENT.get(esf_name)
    if et is None:
        return None
    body = event_block.get(esf_name) or {}

    subject = msg.get("process") if isinstance(msg.get("process"), dict) else {}
    seq = int(msg.get("global_seq_num", msg.get("seq_num", 0)) or 0)
    time = float(msg.get("mach_time", 0) or 0)

    if et == EventType.EXEC:
        payload, argv, env = _payload_exec(body)
        target = body.get("target") if isinstance(body.get("target"), dict) else subject
        proc = process_info(target, argv=argv, env=env)
    elif et in (
        EventType.FILE_CREATE,
        EventType.FILE_WRITE,
        EventType.FILE_RENAME,
        EventType.FILE_UNLINK,
    ):
        payload = _payload_file(body)
        proc = process_info(subject)
    elif et == EventType.FORK:
        child = body.get("child") if isinstance(body.get("child"), dict) else {}
        payload = {"child_pid": _pid(child)} if child else {}
        proc = process_info(subject)
    else:
        payload = _payload_generic(body)
        proc = process_info(subject)

    return Event(
        event_type=et,
        seq=seq,
        time=time,
        pid=proc.pid,
        ppid=proc.ppid if proc.ppid >= 0 else None,
        process=proc,
        payload=payload,
        raw=msg,
    )


def parse_line(line: str) -> Event | None:
    """Parse one JSONL line. Blank, malformed, and unmodeled lines return None.

    A live capture is not always clean JSONL: running eslogger under `script`
    (the PTY wrapper the detonation seam needs — eslogger block-buffers without a
    tty) prepends control bytes (`^D\\x08\\x08`) to the first line, and killing
    eslogger can truncate the last line mid-write. eslogger emits exactly one JSON
    object per line, so anchor on the first `{` and tolerate a decode failure
    rather than aborting the whole capture on one bad line.
    """
    brace = line.find("{")
    if brace < 0:
        return None
    try:
        msg = json.loads(line[brace:])
    except json.JSONDecodeError:
        return None
    return parse_message(msg)


def parse_stream(lines: "Iterator[str] | list[str]") -> Iterator[Event]:
    """Parse an iterable of eslogger JSONL lines into Events, dropping Nones."""
    for line in lines:
        ev = parse_line(line)
        if ev is not None:
            yield ev
