# orchestrator

Python control plane. Owns: the module host + single-threaded event pipeline, the
`DetectionModule` contract and data types (`docs/MODULE_CONTRACT.md`), Detection Score
aggregation, the orchestrator<->detonation API seam (`docs/ARCHITECTURE.md` §8), the
capture/replay harness, and (later) the web backend.
