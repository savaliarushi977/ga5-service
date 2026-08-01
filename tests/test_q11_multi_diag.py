"""Force a multi-diagnostic (fan-out + join) scenario, never exercised by the
original single-diagnostic test, to catch bugs in the untested join-span path."""
import sys
import uuid

import httpx

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://ga5-service-101117070908.asia-south1.run.app"
failures = []


def check(cond, label, extra=""):
    if not cond:
        failures.append(label)
    print(f"[{'OK' if cond else 'FAIL'}] {label} {extra}")


INCIDENT = {
    "profile": "ga5-incident-agent/v2",
    "runId": f"run-multi-{uuid.uuid4().hex}",
    "agentName": "incident-response",
    "publicMarker": "safe-marker-multi",
    "sensitive": {"accessToken": "never export", "privateNote": "never export"},
    "incident": {
        "incidentId": "inc-multi", "title": "Payment failures spiking", "service": "payments", "severity": "SEV-1",
        "transcript": (
            "[ev_cover] Incident opened by monitoring.\n"
            "[ev_db] Database connection pool exhausted at 14:02, correlated with a spike in query latency.\n"
            "[ev_deploy] Deploy of payments-service v9 happened at 14:00.\n"
            "[ev_net] Network partition alert fired for the payments-db subnet at 13:59, one minute before errors.\n"
            "[ev_noise] Someone asked an unrelated question about refunds.\n"
        ),
        "allowedRootCauses": ["bad_deploy_v9", "database_outage", "network_partition"],
    },
    "toolCatalog": [
        {"name": "query_metrics", "description": "Query service error-rate metrics.", "inputSchema": {}},
        {"name": "check_network_health", "description": "Check network partition status for a subnet.", "inputSchema": {}},
        {"name": "check_deploy_log", "description": "Check recent deploy log entries.", "inputSchema": {}},
        {"name": "scale_service", "description": "Scale the service horizontally.", "inputSchema": {}},
    ],
    "policy": {
        "maximumDiagnostics": 3,
        "effectTools": ["scale_service"],
        "approvalRequiredFor": ["rollback_deployment", "disable_feature"],
        "doNotExport": ["accessToken", "privateNote"],
    },
}

r = httpx.post(f"{BASE}/v2/incidents", json=INCIDENT, timeout=30)
check(r.status_code == 200, "POST /v2/incidents returns 200", f"got {r.status_code}: {r.text[:500]}")
resp1 = r.json()
dispatches = resp1.get("dispatches", [])
print(f"got {len(dispatches)} diagnostic dispatch(es)")
for d in dispatches:
    print(f"  {d['toolName']} actionId={d['actionId']} traceparent={d['traceparent']}")

run_id = resp1["runId"]

outcomes = [
    {"actionId": d["actionId"], "callId": d["callId"], "attempt": 1, "status": 200, "resultClass": "diagnosis_confirmed", "nonce": str(uuid.uuid4())}
    for d in dispatches
]
receipt1 = {"receiptId": f"receipt-{uuid.uuid4().hex}", "outcomes": outcomes}
r2 = httpx.post(f"{BASE}/v2/incidents/{run_id}/receipts", json=receipt1, timeout=30)
check(r2.status_code == 200, "POST receipts (diagnostics) returns 200", f"got {r2.status_code}: {r2.text[:500]}")
resp2 = r2.json()
print(f"after diagnostics: status={resp2.get('status')} dispatches={resp2.get('dispatches')}")

# scale_service is NOT in approvalRequiredFor, so it should dispatch directly
effect_dispatches = resp2.get("dispatches", [])
if effect_dispatches:
    effect_id = effect_dispatches[0]["actionId"]
    receipt2 = {"receiptId": f"receipt-{uuid.uuid4().hex}", "outcomes": [
        {"actionId": effect_id, "callId": effect_dispatches[0]["callId"], "attempt": 1, "status": 200, "resultClass": "effect_applied", "nonce": str(uuid.uuid4())}
    ]}
    r3 = httpx.post(f"{BASE}/v2/incidents/{run_id}/receipts", json=receipt2, timeout=30)
    check(r3.status_code == 200, "POST receipts (effect) returns 200", f"got {r3.status_code}: {r3.text[:500]}")
    final = r3.json()
else:
    final = resp2

check(final.get("status") == "completed", "final status is completed", f"got {final.get('status')}")

otlp = final.get("otlp", {})
spans = otlp.get("resourceSpans", [{}])[0].get("scopeSpans", [{}])[0].get("spans", [])
names = [s["name"] for s in spans]
span_ids = [s["spanId"] for s in spans]
check(len(span_ids) == len(set(span_ids)), "all span IDs unique")
if len(dispatches) > 1:
    check("incident.join" in names, "incident.join span present when diagnostics fan out", f"names={names}")
    join_span = next((s for s in spans if s["name"] == "incident.join"), None)
    if join_span:
        check("links" in join_span and len(join_span["links"]) == len(dispatches), "join span links to every diagnostic execute_tool span", f"got {join_span.get('links')}")
else:
    print("(model chose only 1 diagnostic call - join path not exercised this run, retry to test it)")

execute_tool_spans = [n for n in names if n.startswith("execute_tool ")]
check(len(execute_tool_spans) == len(dispatches) + (1 if effect_dispatches else 0), "one execute_tool span per logical action (diagnostics + effect)", f"got {len(execute_tool_spans)} names={execute_tool_spans}")

print()
if failures:
    print(f"{len(failures)} FAILURE(S):", failures)
    raise SystemExit(1)
print("all checks passed")
