# ScratchingPost

A self-hosted payload-analysis sandbox for red teams, targeting **macOS**. The macOS
counterpart to [LitterBox](https://github.com/BlackSnufkin/LitterBox): upload a sample, run it
through static, behavioral, and detection tiers inside a contained macOS environment, and get a
**Detection Score** with a triggering-indicators breakdown before the payload leaves the lab.

Scoring and reporting are adapted from LitterBox, with credit. ScratchingPost never extracts or
redistributes commercial vendors' proprietary detection artifacts (see `docs/ARCHITECTURE.md`
§12).

## Start here

Read the docs in order before writing code:

1. **`docs/ARCHITECTURE.md`** — deployment model (macOS VM appliance), host constraints, tart
   provisioning, ESF telemetry setup, the orchestrator/detonation seam, persistent services.
2. **`docs/MODULE_CONTRACT.md`** — the detection-module interface, the ESF-derived event schema
   and process model, the indicator schema, Detection Score aggregation, capture/replay.
3. **`docs/ROADMAP.md`** — phased build plan (vertical slice first), standalone tools,
   verify-at-build list.

## Repo layout

```
docs/           architecture, module contract, roadmap
orchestrator/   Python: control plane, scoring, module host, UI backend
sensors/        native (Swift/Obj-C/C): ESF recorder, system extension, injection scanner
modules/        detection modules implementing the DetectionModule contract
profiles/       tart golden-image build scripts (per detonation profile)
web/            UI (later phase)
```

## Requirements

Apple Silicon Mac (macOS guests only virtualize on Apple Silicon). See `docs/ARCHITECTURE.md`
§4 for the hard constraints, notably Apple's **2-concurrent-macOS-VM-per-host** kernel cap.

## License

Recommended: **GPL-3.0** (matches LitterBox, enables borrowing its scoring/report code, and is
compatible with Wazuh's GPLv2 and Elastic's open rules). Confirm before the first public commit.

## Security advisory

Development use only. Isolation is the operator's responsibility: run only in isolated VMs or a
dedicated forensics/testing host. This is a professional tool and assumes professional host/VM
separation. No warranty. Users are responsible for legal compliance.
# ScratchingPost
