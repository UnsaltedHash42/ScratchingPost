"""Process model (MODULE_CONTRACT.md §3).

ProcessInfo is the macOS-flavored process node: where heavener carries integrity
level / SID / PE version-info, ScratchingPost carries code-identity fields
(signing, notarization, entitlements, quarantine, csflags) plus behavioral state
accumulated across events. ProcessModel is the dual-indexed tree: by pid for live
lookup, by a stable uid for historical lookup after pid reuse.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# Entitlements that materially widen the attack surface; flagged wherever seen.
DANGEROUS_ENTITLEMENTS: frozenset[str] = frozenset(
    {
        "com.apple.security.get-task-allow",
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.cs.allow-dyld-environment-variables",
        "com.apple.security.cs.allow-unsigned-executable-memory",
        "com.apple.security.cs.disable-executable-page-protection",
    }
)


@dataclass
class ProcessInfo:
    pid: int
    ppid: int
    path: str
    argv: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)  # DYLD_* injection lives here
    responsible_pid: int = -1  # macOS "responsible process" — gamed to inherit TCC grants

    # --- code identity (the macOS detection surface) ---
    team_id: str | None = None
    signing_id: str | None = None
    cdhash: str = ""
    is_platform_binary: bool = False
    signature_type: str = "unsigned"  # unsigned|adhoc|developer_id|app_store|platform
    is_notarized: bool = False
    hardened_runtime: bool = False
    entitlements: dict = field(default_factory=dict)
    quarantine: bool = False  # com.apple.quarantine xattr present
    csflags: int = 0  # runtime code-signing flags (CS_VALID, CS_HARD, ...)

    # --- behavioral state accumulated across events ---
    loaded_dylibs: list[str] = field(default_factory=list)
    injected_by_pid: int | None = None
    task_port_opened_by: int | None = None
    ext: dict = field(default_factory=dict)  # per-process scratch for modules

    def dangerous_entitlements(self) -> list[str]:
        return [k for k in self.entitlements if k in DANGEROUS_ENTITLEMENTS]

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "ppid": self.ppid,
            "path": self.path,
            "argv": list(self.argv),
            "env": dict(self.env),
            "responsible_pid": self.responsible_pid,
            "team_id": self.team_id,
            "signing_id": self.signing_id,
            "cdhash": self.cdhash,
            "is_platform_binary": self.is_platform_binary,
            "signature_type": self.signature_type,
            "is_notarized": self.is_notarized,
            "hardened_runtime": self.hardened_runtime,
            "entitlements": self.entitlements,
            "quarantine": self.quarantine,
            "csflags": self.csflags,
            "loaded_dylibs": list(self.loaded_dylibs),
            "injected_by_pid": self.injected_by_pid,
            "task_port_opened_by": self.task_port_opened_by,
            "ext": self.ext,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ProcessInfo":
        return cls(
            pid=int(d["pid"]),
            ppid=int(d.get("ppid", -1)),
            path=d.get("path", ""),
            argv=list(d.get("argv", [])),
            env=dict(d.get("env", {})),
            responsible_pid=int(d.get("responsible_pid", -1)),
            team_id=d.get("team_id"),
            signing_id=d.get("signing_id"),
            cdhash=d.get("cdhash", ""),
            is_platform_binary=bool(d.get("is_platform_binary", False)),
            signature_type=d.get("signature_type", "unsigned"),
            is_notarized=bool(d.get("is_notarized", False)),
            hardened_runtime=bool(d.get("hardened_runtime", False)),
            entitlements=d.get("entitlements", {}) or {},
            quarantine=bool(d.get("quarantine", False)),
            csflags=int(d.get("csflags", 0)),
            loaded_dylibs=list(d.get("loaded_dylibs", [])),
            injected_by_pid=d.get("injected_by_pid"),
            task_port_opened_by=d.get("task_port_opened_by"),
            ext=d.get("ext", {}) or {},
        )


class ProcessModel:
    """Dual-indexed process tree.

    `by_pid` is the live view (current occupant of a pid). `by_uid` retains every
    node ever seen, keyed by a stable uid, so a module can still resolve a node
    after its pid was reused by a later exec. uids are deterministic
    (``{pid}-{seq}``) so replaying a capture rebuilds an identical model.
    """

    def __init__(self) -> None:
        self.by_pid: dict[int, ProcessInfo] = {}
        self.by_uid: dict[str, ProcessInfo] = {}
        self._uid_of: dict[int, str] = {}  # pid -> uid of current occupant

    @staticmethod
    def _uid(pid: int, seq: int) -> str:
        return f"{pid}-{seq}"

    def get(self, pid: int) -> ProcessInfo | None:
        return self.by_pid.get(pid)

    def get_by_uid(self, uid: str) -> ProcessInfo | None:
        return self.by_uid.get(uid)

    def uid_for_pid(self, pid: int) -> str | None:
        return self._uid_of.get(pid)

    def insert(self, proc: ProcessInfo, seq: int) -> str:
        """Install `proc` as the live occupant of its pid, retiring any prior
        occupant into the historical index. Returns the node's uid."""
        uid = self._uid(proc.pid, seq)
        self.by_pid[proc.pid] = proc
        self.by_uid[uid] = proc
        self._uid_of[proc.pid] = uid
        return uid

    def mark_exit(self, pid: int) -> None:
        """Drop the pid from the live view but keep the node in `by_uid`."""
        self.by_pid.pop(pid, None)
        self._uid_of.pop(pid, None)
