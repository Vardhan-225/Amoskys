import requests, time

def test_latency_budget():
    # assumes services running under compose
    for _ in range(20):
        r = requests.get("http://localhost:9090/api/v1/query",
                         params={"query":"agent_publish_latency_ms:p95_5m"})
        v = float(r.json()["data"]["result"][0]["value"][1]) if r.json()["data"]["result"] else 0.0
        if v > 0: break
        time.sleep(3)
    # Budget: < 50ms
    assert v < 50.0, f"p95 too high: {v}ms"
