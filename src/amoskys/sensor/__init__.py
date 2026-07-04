"""AMOSKYS 2.0 sensor bridge — connects the kernel-witness sensor to the Brain.

The Rust sensor (``sensor/``) consumes the ESF event stream (Phase 0 source:
Apple ``eslogger``; Phase 1 source: the native Swift ESF System Extension) and
emits normalized, code-signing-trust-classified events as JSON. This package
converts that stream into the same ``DeviceTelemetry`` protobuf the Python
agents emit, so kernel-witnessed events flow through the existing analyzer →
shipper → Brain → dashboard pipeline unchanged.
"""
