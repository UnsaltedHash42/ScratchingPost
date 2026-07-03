"""Native-ish macOS sensors feeding the uniform event schema.

Phase 1: the ESF recorder is a Python subprocess wrapper around Apple's stock
/usr/bin/eslogger (no native code yet). Phase 2+ replaces it with a custom
EndpointSecurity system extension. See docs/ARCHITECTURE.md §7.
"""
