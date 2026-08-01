import sys
import time
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
    "runId": f"run-{uuid.uuid4().hex}",
    "agentName": "incident-response",
    "publicMarker": "safe-marker-1",
    "sensitive": {"accessToken": "never export", "privateNote": "never export"},
    "incident": {
        "incidentId": "inc-1", "title": "Checkout errors spiking", "service": "checkout", "severity": "SEV-1",
        "transcript": (
            "[ev_cover] Incident opened by monitoring.\n"
            "[ev_noise1] Someone mentioned the weather is nice today.\n"
            "[ev_db] Database connection pool exhausted at 14:02 after a deploy of checkout-service v42.\n"
            "[ev_deploy] Deploy of checkout-service v42 happened at 14:00, two minutes before errors started.\n"
            "[ev_noise2] Customer asked an unrelated question about refunds.\n"
        ),
        "allowedRootCauses": ["bad_deploy_v42", "database_outage", "network_partition"],
    },
    "toolCatalog": [
        {"name": "query_metrics", "description": "Query service error-rate metrics.", "inputSchema": {}},
        {"name": "check_deploy_log", "description": "Check recent deploy log entries.", "inputSchema": {}},
        {"name": "rollback_deployment", "description": "Roll back to the previous deployment.", "inputSchema": {}},
        {"name": "scale_service", "description": "Scale the service horizontally.", "inputSchema": {}},
    ],
    "policy": {
        "maximumDiagnostics": 2,
        "effectTools": ["rollback_deployment"],
        "approvalRequiredFor": ["rollback_deployment", "disable_feature"],
        "doNotExport": ["accessToken", "privateNote"],
    },
}

r = httpx.post(f"{BASE}/v2/incidents", json=INCIDENT, timeout=30)
check(r.status_code == 200, "POST /v2/incidents returns 200", f"got {r.status_code}: {r.text[:300]}")
resp1 = r.json()
check(resp1.get("status") == "waiting", "initial status is waiting")
diagnosis = resp1.get("diagnosis", {})
check(diagnosis.get("rootCause") in INCIDENT["incident"]["allowedRootCauses"], "root cause is one of the allowed values", f"got {diagnosis.get('rootCause')}")
check(2 <= len(diagnosis.get("evidence", [])) <= 4, "diagnosis cites 2-4 evidence ids", f"got {diagnosis.get('evidence')}")
dispatches = resp1.get("dispatches", [])
check(1 <= len(dispatches) <= INCIDENT["policy"]["maximumDiagnostics"], "dispatch count within maximumDiagnostics", f"got {len(dispatches)}")
check(all(d["phase"] == "diagnostic" for d in dispatches), "all initial dispatches are diagnostic phase")
check(all(d["traceparent"].startswith("00-") and len(d["traceparent"].split("-")[1]) == 32 for d in dispatches), "traceparent well-formed")
check(all(any(e in diagnosis["evidence"] for e in d["evidence"]) for d in dispatches), "each diagnostic dispatch cites diagnosis evidence")

run_id = resp1["runId"]
print()
for d in dispatches:
    print(f"  dispatch: {d['toolName']} actionId={d['actionId']} evidence={d['evidence']}")
print()

# --- replay identical request -> byte-equivalent ---
r_replay = httpx.post(f"{BASE}/v2/incidents", json=INCIDENT, timeout=15)
check(r_replay.status_code == 200 and r_replay.json() == resp1, "replay of identical incident submission is byte-equivalent")

# --- send diagnostic outcomes (all confirmed) ---
outcomes = [
    {"actionId": d["actionId"], "callId": d["callId"], "attempt": 1, "status": 200, "resultClass": "diagnosis_confirmed", "nonce": str(uuid.uuid4())}
    for d in dispatches
]
receipt1 = {"receiptId": f"receipt-{uuid.uuid4().hex}", "outcomes": outcomes}
r2 = httpx.post(f"{BASE}/v2/incidents/{run_id}/receipts", json=receipt1, timeout=30)
check(r2.status_code == 200, "POST receipts (diagnostics) returns 200", f"got {r2.status_code}: {r2.text[:300]}")
resp2 = r2.json()
check(resp2.get("status") == "waiting", "after diagnostics, status still waiting (approval needed)")
approvals = resp2.get("approvals", [])
check(len(approvals) == 1 and approvals[0]["toolName"] == "rollback_deployment", "approval requested for destructive effect", f"got {approvals}")

approval_id = approvals[0]["approvalId"]
approval_nonce = str(uuid.uuid4())
receipt2 = {"receiptId": f"receipt-{uuid.uuid4().hex}", "outcomes": [], "approvals": [{"approvalId": approval_id, "decision": "approved", "nonce": approval_nonce}]}
r3 = httpx.post(f"{BASE}/v2/incidents/{run_id}/receipts", json=receipt2, timeout=30)
check(r3.status_code == 200, "POST receipts (approval) returns 200", f"got {r3.status_code}: {r3.text[:300]}")
resp3 = r3.json()
effect_dispatches = resp3.get("dispatches", [])
check(len(effect_dispatches) == 1 and effect_dispatches[0]["toolName"] == "rollback_deployment", "effect dispatched after approval", f"got {effect_dispatches}")
check(effect_dispatches[0]["phase"] == "effect", "effect dispatch has phase=effect")

effect_action_id = effect_dispatches[0]["actionId"]
receipt3 = {"receiptId": f"receipt-{uuid.uuid4().hex}", "outcomes": [
    {"actionId": effect_action_id, "callId": effect_dispatches[0]["callId"], "attempt": 1, "status": 200, "resultClass": "effect_applied", "nonce": str(uuid.uuid4())}
]}
r4 = httpx.post(f"{BASE}/v2/incidents/{run_id}/receipts", json=receipt3, timeout=30)
check(r4.status_code == 200, "POST receipts (effect outcome) returns 200", f"got {r4.status_code}: {r4.text[:300]}")
resp4 = r4.json()
check(resp4.get("status") == "completed", "final status is completed", f"got {resp4.get('status')}")
check(resp4.get("chosenEffect") == "rollback_deployment", "chosenEffect recorded")
check("actionLog" in resp4 and "receiptLog" in resp4, "actionLog and receiptLog both present")
check("otlp" in resp4, "otlp field present")

otlp = resp4.get("otlp", {})
spans = otlp.get("resourceSpans", [{}])[0].get("scopeSpans", [{}])[0].get("spans", [])
names = [s["name"] for s in spans]
check(any(s["kind"] == 2 for s in spans), "an OTLP span has SERVER kind (2)")
check("invoke_agent incident-response" in names, "invoke_agent span present")
check(sum(1 for n in names if n == "chat incident-plan") == 1, "exactly one chat incident-plan span")
check(any(n.startswith("execute_tool ") for n in names), "execute_tool span(s) present")
check(any(n.startswith("POST tool/") for n in names), "CLIENT tool POST span(s) present")
check(any(n == "approval_gate" for n in names), "approval_gate span present")

trace_ids = {s["traceId"] for s in spans}
check(len(trace_ids) == 1, "all spans share a single traceId")

for s in spans:
    attrs = {a["key"] for a in s.get("attributes", [])}
    check("ga5.run.id" in attrs and "ga5.public.marker" in attrs, f"span {s['name']} carries ga5.run.id + ga5.public.marker")

serialized = str(resp4)
check("never export" not in serialized, "sensitive values never appear in the response")
check(INCIDENT["incident"]["transcript"] not in serialized, "raw transcript not exported verbatim")

# --- GET run ---
r5 = httpx.get(f"{BASE}/v2/incidents/{run_id}", timeout=15)
check(r5.status_code == 200 and r5.json().get("status") == "completed", "GET run returns completed state")

print()
if failures:
    print(f"{len(failures)} FAILURE(S):", failures)
    raise SystemExit(1)
print("all checks passed")
