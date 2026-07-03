# Behavior demo samples

Self-acting Mach-O samples that perform a real malicious *behavior* on launch, so a
fire-and-forget detonation (~12 s, no C2 tasking) trips ScratchingPost's behavioral
detection content — not just the "an unsigned binary ran" signal (rule 100020).

These close ROADMAP limitation 2 ("detection is shallow"): the interesting Wazuh rules
(persistence, injection, LaunchAgent drops) only fire when the sample actually performs
the action. A live C2 implant needs tasking over its channel to do that; a self-acting
sample does it on `main()`, inside the existing detonation window.

| sample | behavior | fires |
|---|---|---|
| `persist_launchagent` | drops a plist into `~/Library/LaunchAgents/` (does **not** load it) | rule **100010** — LaunchAgents persistence, MITRE **T1543.001** (+ 100020 on its own adhoc exec) |
| `inject_taskport` | forks a child and acquires its Mach task port with `task_for_pid` (the surviving macOS injection primitive) | rule **100001** — task-port acquisition, MITRE **T1055** (+ 100020 on its own adhoc exec) |

Adhoc-signed, so each also trips 100020 (T1553) on exec — but the point is the behavior
rule. They only act inside the disposable clone (reverted after the run) and never load or
register anything, so nothing persists on the host. `inject_taskport` targets a plain
`fork()` of itself (same uid, adhoc, no hardened runtime; it also self-signs with
`get-task-allow`), so `task_for_pid` succeeds without exotic privileges and on the guest
(root, SIP disabled) it is unrestricted. It only reads the child's task port and kills the
child — no `mach_vm_write`, no remote thread.

## Build

```sh
./build.sh          # needs Xcode CLT on an Apple-Silicon Mac
```

## Detonate (wazuh profile, proves the behavior rule fires end-to-end)

Detonate through the same wired path as `tests/test_wazuh_e2e.py` (host-side eslogger
capture → scoped to the sample's process subtree → pushed to the in-guest Wazuh agent →
manager rules fire → indexer → dispatch tier). The capture is scoped to the sample's own
pid/`responsible_pid` lineage, so the LaunchAgents write is attributed to the sample and
system noise is dropped. Point a live `LocalAppliance(golden_images={"wazuh": ...},
agent_ingest_path=..., detonate_settle=20, eslogger_start_delay=3)` at the built binary.
