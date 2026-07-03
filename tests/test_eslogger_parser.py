from pathlib import Path

from orchestrator.contracts.events import EventType
from sensors.eslogger import parse_line, parse_stream

FIX = Path(__file__).parent / "fixtures" / "eslogger" / "sample_capture.jsonl"


def _events():
    return list(parse_stream(FIX.read_text().splitlines()))


def test_unmodeled_event_dropped_but_others_kept():
    evs = _events()
    # 5 lines: exec, create, fork, access(unmodeled -> dropped), exit
    types = [e.event_type for e in evs]
    assert EventType.EXEC in types
    assert EventType.FILE_CREATE in types
    assert EventType.FORK in types
    assert EventType.EXIT in types
    assert len(evs) == 4  # access dropped


def test_exec_maps_target_identity_and_env():
    exec_ev = next(e for e in _events() if e.event_type == EventType.EXEC)
    assert exec_ev.pid == 501
    assert exec_ev.ppid == 499
    proc = exec_ev.process
    assert proc.path == "/tmp/payload"
    assert proc.argv == ["/tmp/payload", "--go"]
    # env list -> dict, DYLD injection visible
    assert proc.env["DYLD_INSERT_LIBRARIES"] == "/tmp/evil.dylib"
    # codesigning_flags 2 == CS_ADHOC
    assert proc.signature_type == "adhoc"
    assert proc.cdhash == "aabbccdd"
    assert exec_ev.payload["cwd"] == "/tmp"


def test_create_carries_path():
    ev = next(e for e in _events() if e.event_type == EventType.FILE_CREATE)
    assert ev.payload["path"] == "/tmp/dropped.bin"
    assert ev.pid == 501


def test_fork_extracts_child_pid():
    ev = next(e for e in _events() if e.event_type == EventType.FORK)
    assert ev.payload["child_pid"] == 777


def test_seq_and_provenance_preserved():
    ev = parse_line(FIX.read_text().splitlines()[0])
    assert ev.seq == 1
    assert ev.raw is not None and "event" in ev.raw


def test_blank_line_returns_none():
    assert parse_line("   ") is None


def test_script_pty_prefix_on_first_line_still_parses():
    # eslogger run under `script` (the PTY wrapper the live seam needs) prepends
    # control bytes to the first captured line; parse_line anchors on the first `{`.
    clean = FIX.read_text().splitlines()[0]
    assert parse_line("^D\x08\x08" + clean) is not None


def test_malformed_line_returns_none():
    # A line truncated mid-write (eslogger killed) must be dropped, not raise.
    assert parse_line('{"event":{"exec":') is None
    assert parse_line("not json at all") is None


# -- reconciliation against a REAL macOS 26.5.2 (Tahoe) eslogger capture --------
REAL = Path(__file__).parent / "fixtures" / "eslogger" / "real_tahoe_capture.jsonl"


def _real_events():
    return {e.event_type: e for e in parse_stream(REAL.read_text().splitlines())}


def test_real_capture_all_kinds_parse():
    evs = _real_events()
    for et in (EventType.EXEC, EventType.FORK, EventType.FILE_CREATE,
               EventType.FILE_RENAME, EventType.FILE_UNLINK):
        assert et in evs, f"{et} missing from real capture parse"


def test_real_exec_identity_from_target():
    ev = _real_events()[EventType.EXEC]
    proc = ev.process
    assert proc.pid > 0 and proc.path.startswith("/")
    # real platform binary: is_platform_binary True, classified "platform"
    assert proc.is_platform_binary is True
    assert proc.signature_type == "platform"
    assert proc.signing_id  # e.g. com.apple.xpc.proxy
    assert len(proc.cdhash) == 40  # sha1 hex string, as ES renders it


def test_real_rename_captures_source_and_full_dest():
    # The reconciliation fix: rename must expose source.path AND a full destination
    # path (new_path.dir + filename), not just the bare filename.
    ev = _real_events()[EventType.FILE_RENAME]
    assert ev.payload["path"].startswith("/private/tmp/spd_")      # source, full path
    assert ev.payload["dest"].startswith("/private/tmp/spdm_")     # dest, dir+filename joined
    assert "/" in ev.payload["dest"]


def test_real_unlink_and_create_paths():
    evs = _real_events()
    assert evs[EventType.FILE_UNLINK].payload["path"].startswith("/private/tmp/spdm_")
    assert evs[EventType.FILE_CREATE].payload["path"].startswith("/private/tmp/spd_")
