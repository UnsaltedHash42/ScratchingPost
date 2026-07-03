from orchestrator.contracts.events import Event, EventType
from orchestrator.contracts.process import ProcessInfo
from orchestrator.pipeline import ModuleHost, read_capture, replay_events, write_capture

from tests.support import ExecWatchModule


def _scenario() -> list[Event]:
    """A tiny dylib-injection scenario, intentionally out of seq order on disk."""
    inj = ProcessInfo(pid=501, ppid=499, path="/tmp/payload", env={"DYLD_INSERT_LIBRARIES": "/tmp/evil.dylib"})
    child = ProcessInfo(pid=777, ppid=501, path="/tmp/payload")
    return [
        Event(EventType.EXIT, seq=4, time=4, pid=501, ppid=499),
        Event(EventType.EXEC, seq=1, time=1, pid=501, ppid=499, process=inj,
              payload={"target_path": "/tmp/payload"}),
        Event(EventType.FORK, seq=2, time=2, pid=501, ppid=499, payload={"child_pid": 777}, process=child),
        Event(EventType.DYLIB_LOAD, seq=3, time=3, pid=501, payload={"path": "/tmp/evil.dylib"}),
    ]


def test_pipeline_orders_by_seq():
    mod = ExecWatchModule()
    replay_events(_scenario(), [mod])
    # Delivered in ascending seq regardless of on-disk order.
    assert mod.seen_order == [1, 2, 3, 4]


def test_process_model_maintained_by_host():
    inj = ProcessInfo(pid=501, ppid=499, path="/tmp/payload")
    with ModuleHost([]) as host:
        host.submit(Event(EventType.EXEC, seq=1, time=1, pid=501, ppid=499, process=inj))
        host.submit(Event(EventType.FORK, seq=2, time=2, pid=501, payload={"child_pid": 777},
                          process=ProcessInfo(pid=777, ppid=501, path="/tmp/payload")))
        host.submit(Event(EventType.DYLIB_LOAD, seq=3, time=3, pid=501, payload={"path": "/tmp/evil.dylib"}))
    assert host.model.get(501).loaded_dylibs == ["/tmp/evil.dylib"]
    assert host.model.get(777).ppid == 501


def test_replay_is_idempotent(tmp_path):
    capture = tmp_path / "scenario.jsonl"
    n = write_capture(capture, _scenario())
    assert n == 4

    first = [i.to_dict() for i in replay_events(read_capture(capture), [ExecWatchModule()])]
    second = [i.to_dict() for i in replay_events(read_capture(capture), [ExecWatchModule()])]
    assert first == second  # deterministic FNV-1a IDs -> byte-identical replays

    # The injecting exec is flagged with the DYLD technique.
    ids = {i["name"]: i for i in first}
    assert "exec-observed" in ids
    assert any("T1574.006" in i["attack"] for i in first)


def test_worker_error_surfaces_on_stop():
    class Boom(ExecWatchModule):
        def on_event(self, event, model):
            raise ValueError("boom")

    import pytest
    with pytest.raises(ValueError, match="boom"):
        host = ModuleHost([Boom()])
        host.start()
        host.submit(Event(EventType.EXEC, seq=1, time=1, pid=1, ppid=0,
                          process=ProcessInfo(pid=1, ppid=0, path="/x")))
        host.stop()
