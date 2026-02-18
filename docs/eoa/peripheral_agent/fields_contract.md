# PeripheralAgent V2 — Evidence Richness Contract

## Proto Pattern

All events follow the `DeviceTelemetry → TelemetryEvent` structure:

| Layer | Proto Type | Key Fields |
|---|---|---|
| Envelope | `DeviceTelemetry` | `device_id`, `device_type="HOST"`, `protocol="USB"`, `timestamp_ns`, `collection_agent="peripheral_agent_v2"` |
| Metric | `TelemetryEvent.metric_data` | `event_type="METRIC"`, `metric_name`, `numeric_value`, `unit` |
| Security | `TelemetryEvent.security_event` | `event_type="SECURITY"`, `SecurityEvent.mitre_techniques`, `SecurityEvent.risk_score`, `attributes` map |

## METRIC Events (heartbeats)

| Metric Name | Source | Unit | Description |
|---|---|---|---|
| `peripheral_events_collected` | `peripheral_collector` | events | Probe output count per cycle (0 = no probes fired but agent alive) |
| `peripheral_probe_events` | `peripheral_agent` | events | Same as above, emitted only when >0 |

## SECURITY Events (probe findings)

| Event Category | Probe | MITRE | Risk Score | Attributes |
|---|---|---|---|---|
| `usb_inventory_snapshot` | `usb_inventory` | T1200 | 0.4 | `device_count`, `devices` (JSON list) |
| `usb_device_connected` | `usb_connection_edge` | T1200, T1091 | 0.4–0.8 | `device_id`, `name`, `vendor_id`, `product_id`, `manufacturer` |
| `usb_device_disconnected` | `usb_connection_edge` | T1200 | 0.4 | `device_id`, `name` |
| `usb_storage_detected` | `usb_storage` | T1091, T1052 | 0.8 | `device_id`, `name`, `exfiltration_risk` |
| `usb_network_adapter_detected` | `usb_network_adapter` | T1557 | 0.8 | `device_id`, `name`, `adapter_type` |
| `new_keyboard_detected` | `hid_keyboard_mouse_anomaly` | T1056.001 | 0.8 | `device_id`, `name`, `badusb_risk` |
| `bluetooth_device_found` | `bluetooth_device` | T1200 | 0.4 | `address`, `name`, `device_type`, `connected` |
| `peripheral_risk_assessment` | `high_risk_peripheral_score` | T1200 | varies | `risk_score`, `risk_factors` |

## Evidence Guarantees

1. Every `SECURITY` event has a non-empty `security_event.mitre_techniques` list
2. Every `SECURITY` event has a non-empty `attributes` map with probe evidence
3. Every cycle emits at least 1 `METRIC` event (heartbeat proves liveness)
4. `confidence_score` is set on all `SECURITY` events (from probe's `_create_event()`)
5. No events reference non-existent proto fields (`PeripheralTelemetry`, `AlertData`, `alerts`)

## Dark Spots

- 6/7 probes require physical USB/Bluetooth hardware to trigger
- No Thunderbolt/PCIe DMA monitoring
- BadUSB detection is heuristic (name/timing-based), not firmware analysis
