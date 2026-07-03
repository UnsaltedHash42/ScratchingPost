# sensors

Native macOS sensors that feed the uniform event schema.

- **Phase 1:** the ESF recorder is a Python subprocess wrapper around Apple's stock
  `/usr/bin/eslogger` (no native code yet). It lives here for cohesion but is Python for now.
- **Phase 2+:** a custom **EndpointSecurity system extension** (Swift/Obj-C) for AUTH events,
  path muting, and richer enrichment; and the **mach_vm_region injection scanner** (C/Swift).

See `docs/ARCHITECTURE.md` §7 for provisioning and `docs/MODULE_CONTRACT.md` §3 for the schema.
