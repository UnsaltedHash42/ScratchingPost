from orchestrator.contracts import (
    Event,
    EventType,
    Indicator,
    ProcessInfo,
    ProcessModel,
    Severity,
    Tier,
    fnv1a_64,
    indicator_id,
)


def test_fnv1a_known_vector():
    # FNV-1a/64 of the empty string is the offset basis.
    assert fnv1a_64("") == 0xCBF29CE484222325
    # "a" -> offset ^ 0x61 * prime, well-known value.
    assert fnv1a_64("a") == 0xAF63DC4C8601EC8C


def test_indicator_id_deterministic_and_unique():
    a = indicator_id("mod", "name", "/tmp/x")
    b = indicator_id("mod", "name", "/tmp/x")
    c = indicator_id("mod", "name", "/tmp/y")
    assert a == b
    assert a != c
    assert len(a) == 16
    # separator prevents field-boundary collisions.
    assert indicator_id("ab", "c") != indicator_id("a", "bc")


def test_indicator_roundtrip():
    ind = Indicator(
        id="deadbeef", name="n", severity=Severity.HIGH, tier=Tier.STATIC,
        module="m", attack=["T1553.001"], description="d", evidence={"k": 1},
    )
    assert Indicator.from_dict(ind.to_dict()) == ind


def test_event_roundtrip_with_process():
    proc = ProcessInfo(pid=10, ppid=1, path="/bin/x", argv=["x"], env={"DYLD_INSERT_LIBRARIES": "/e"})
    ev = Event(event_type=EventType.EXEC, seq=3, time=1.0, pid=10, ppid=1, process=proc, payload={"a": 1})
    back = Event.from_dict(ev.to_dict())
    assert back.event_type == EventType.EXEC
    assert back.seq == 3 and back.pid == 10
    assert back.process.env == {"DYLD_INSERT_LIBRARIES": "/e"}


def test_process_model_dual_index_and_pid_reuse():
    m = ProcessModel()
    p1 = ProcessInfo(pid=100, ppid=1, path="/first")
    uid1 = m.insert(p1, seq=1)
    assert m.get(100) is p1
    assert m.get_by_uid(uid1) is p1

    # pid 100 reused by a later exec: live view updates, history is retained.
    p2 = ProcessInfo(pid=100, ppid=1, path="/second")
    uid2 = m.insert(p2, seq=2)
    assert uid1 != uid2
    assert m.get(100) is p2                 # live lookup -> new occupant
    assert m.get_by_uid(uid1) is p1         # historical lookup -> old node survives
    assert m.get_by_uid(uid2) is p2

    m.mark_exit(100)
    assert m.get(100) is None
    assert m.get_by_uid(uid2) is p2         # still resolvable historically


def test_dangerous_entitlements():
    p = ProcessInfo(
        pid=1, ppid=0, path="/x",
        entitlements={
            "com.apple.security.get-task-allow": True,
            "com.apple.security.app-sandbox": True,
        },
    )
    assert p.dangerous_entitlements() == ["com.apple.security.get-task-allow"]
