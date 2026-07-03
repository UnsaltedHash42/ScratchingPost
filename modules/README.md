# modules

Detection modules implementing `DetectionModule` (`docs/MODULE_CONTRACT.md` §2). Four tiers:
static, behavioral, offline-emulation (Apple built-in, Elastic), real-agent-dispatch (Wazuh,
commercial). Each emits `Indicator`s with ATT&CK tags into the Detection Score.
