# Backpressure Runbook

## Symptoms
- Alerts: BusInflightHigh, RetryStorm
- Grafana: bus_inflight_requests rising; agent_publish_retry_total rate spikes
- Agent WAL backlog growing

## Checklist (in order)
1) Confirm Bus healthz (8080) is OK.
2) Check EventBus CPU/mem; raise limits if exhausted.
3) Increase BUS_MAX_INFLIGHT cautiously (e.g., +25%) if CPU headroom exists.
4) Verify no jumbo envelopes: scan logs for "envelope too large".
5) If WAL backlog > 200MB, raise disk or tighten source rate:
   - temporarily reduce agent send rate (IS_SEND_RATE env), or enable sampling.
6) If dedupe is high, investigate producer duplicates.
7) After stabilization, reset BUS_MAX_INFLIGHT and tune permanently.

## Preventative
- Set alerts on p95 latency, inflight, retry rate.
- Keep payloads <128KB; enforce at agent.
- Capacity-plan: N agents × R events/s ≤ BUS_MAX_INFLIGHT * (processing rate).
