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


TOKEN_A = f"tok-a-{uuid.uuid4().hex}"
TOKEN_B = f"tok-b-{uuid.uuid4().hex}"
HEADERS_A = {"Authorization": f"Bearer {TOKEN_A}", "A2A-Version": "1.0", "Content-Type": "application/a2a+json"}
HEADERS_B = {"Authorization": f"Bearer {TOKEN_B}", "A2A-Version": "1.0", "Content-Type": "application/a2a+json"}

# --- Agent Card ---
r = httpx.get(f"{BASE}/.well-known/agent-card.json", timeout=15)
check(r.status_code == 200, "agent card returns 200")
card = r.json()
check(bool(card.get("name")) and bool(card.get("description")) and bool(card.get("version")), "card has nonempty name/description/version")
skill = next((s for s in card.get("skills", []) if s.get("name") == "invoice_action_agent"), None)
check(skill is not None, "card has invoice_action_agent skill")
iface = card.get("supportedInterfaces", [{}])[0]
check(iface.get("protocolBinding") == "HTTP+JSON" and iface.get("protocolVersion") == "1.0", "supportedInterfaces has correct protocol binding/version")
check("application/vnd.ga5.invoice-claim-batch+json" in card.get("defaultInputModes", []), "defaultInputModes includes claim-batch media type")
out_modes = card.get("defaultOutputModes", [])
check(
    "application/vnd.ga5.invoice-action-proposals+json" in out_modes and "application/vnd.ga5.invoice-action-receipts+json" in out_modes,
    "defaultOutputModes includes both proposal and receipt media types",
)

# --- Auth / version / media-type checks ---
r = httpx.post(f"{BASE}/a2a/message:send", json={}, headers={"A2A-Version": "1.0", "Content-Type": "application/a2a+json"}, timeout=15)
check(r.status_code == 401, "missing auth (version/content-type present) -> 401", f"got {r.status_code}")
r = httpx.post(f"{BASE}/a2a/message:send", json={}, headers={**HEADERS_A, "A2A-Version": "2.0"}, timeout=15)
check(r.status_code == 400, "wrong A2A-Version -> 400", f"got {r.status_code}")
r = httpx.post(f"{BASE}/a2a/message:send", json={}, timeout=15)
check(r.status_code == 401, "everything missing -> 401 (auth checked first)", f"got {r.status_code}")
r = httpx.get(f"{BASE}/a2a/tasks", timeout=15)
check(r.status_code == 401, "GET /tasks with no auth at all -> 401", f"got {r.status_code}")
r = httpx.post(f"{BASE}/a2a/message:send", json={}, headers={**HEADERS_A, "Content-Type": "application/json"}, timeout=15)
check(r.status_code == 400, "wrong Content-Type -> 400", f"got {r.status_code}")

# --- Fresh batch submission ---
PACKAGES = [
    {"packageId": "pkg-1", "text": "[p1-cover] Cover sheet, ignore. [p1-fact] Invoice INV-100 from Acme Co for 50000 paise, matches PO and goods receipt exactly, within our 100000 paise autonomous limit."},
    {"packageId": "pkg-2", "text": "[p2-cover] Cover sheet. [p2-fact] Invoice INV-200 from Globex for 900000 paise, exceeds our 100000 paise autonomous authority, needs manager sign-off."},
    {"packageId": "pkg-3", "text": "[p3-cover] Cover. [p3-dup] Invoice INV-300 from Acme Co was already paid in full last month per ledger entry L-88; this is the same invoice number resubmitted."},
]

message_id_1 = f"msg-{uuid.uuid4().hex}"
send_req = {
    "message": {
        "messageId": message_id_1,
        "role": "ROLE_USER",
        "parts": [{
            "mediaType": "application/vnd.ga5.invoice-claim-batch+json",
            "data": {"batchId": "batch-1", "policyRevision": "rev1", "packages": PACKAGES},
        }],
    },
    "configuration": {
        "returnImmediately": False, "historyLength": 20,
        "acceptedOutputModes": ["application/vnd.ga5.invoice-action-proposals+json", "application/vnd.ga5.invoice-action-receipts+json"],
    },
}
r = httpx.post(f"{BASE}/a2a/message:send", json=send_req, headers=HEADERS_A, timeout=60)
check(r.status_code == 200, "message:send (fresh batch) returns 200", f"got {r.status_code}: {r.text[:300]}")
task1 = r.json()
check(task1.get("status", {}).get("state") == "TASK_STATE_INPUT_REQUIRED", "task state is INPUT_REQUIRED")
proposals_artifact = next((a for a in task1.get("artifacts", []) if a["mediaType"] == "application/vnd.ga5.invoice-action-proposals+json"), None)
check(proposals_artifact is not None, "exactly one proposals artifact present")
proposals = proposals_artifact["data"]["proposals"] if proposals_artifact else []
check(len(proposals) == len(PACKAGES), "one proposal per package", f"got {len(proposals)}")

by_pkg = {p["packageId"]: p for p in proposals}
print()
for p in proposals:
    print(f"  {p['packageId']}: action={p['action']} evidenceRefs={p['evidenceRefs']} rationale_len={len(p['rationale'])}")
print()

check(by_pkg.get("pkg-1", {}).get("action") == "settle_invoice", "within-authority matching invoice -> settle_invoice")
check(by_pkg.get("pkg-2", {}).get("action") == "request_approval", "over-authority invoice -> request_approval")
check(by_pkg.get("pkg-3", {}).get("action") == "reject_duplicate", "already-paid invoice -> reject_duplicate")
check(all(60 <= len(p["rationale"]) <= 1500 for p in proposals), "rationale length within 60-1500 chars")
check(all(len(p.get("evidenceRefs", [])) >= 1 for p in proposals), "every proposal has at least one evidence ref")

action_ids = [p["actionId"] for p in proposals]
check(len(action_ids) == len(set(action_ids)) and all(len(a) >= 12 for a in action_ids), "actionIds unique and >=12 chars")

task_id = task1["id"]
context_id = task1["contextId"]

# --- replay same messageId, same content -> byte-equivalent ---
r2 = httpx.post(f"{BASE}/a2a/message:send", json=send_req, headers=HEADERS_A, timeout=30)
check(r2.status_code == 200 and r2.json() == task1, "replay of identical message:send is byte-equivalent")

# --- results continuation ---
results_msg_id = f"msg-{uuid.uuid4().hex}"
results_req = {
    "message": {
        "messageId": results_msg_id, "taskId": task_id, "contextId": context_id,
        "role": "ROLE_USER",
        "parts": [{
            "mediaType": "application/vnd.ga5.invoice-action-results+json",
            "data": {"batchId": "batch-1", "results": [
                {"packageId": p["packageId"], "actionId": p["actionId"], "action": p["action"], "outcome": "ACCEPTED", "receiptNonce": f"nonce-{i}"}
                for i, p in enumerate(proposals)
            ]},
        }],
    },
}
r3 = httpx.post(f"{BASE}/a2a/message:send", json=results_req, headers=HEADERS_A, timeout=30)
check(r3.status_code == 200, "results continuation returns 200", f"got {r3.status_code}: {r3.text[:300]}")
task_completed = r3.json()
check(task_completed.get("status", {}).get("state") == "TASK_STATE_COMPLETED", "task state is COMPLETED after results")
receipts_artifact = next((a for a in task_completed.get("artifacts", []) if a["mediaType"] == "application/vnd.ga5.invoice-action-receipts+json"), None)
check(receipts_artifact is not None, "receipts artifact present")
executions = receipts_artifact["data"]["executions"] if receipts_artifact else []
check(len(executions) == len(proposals), "all accepted results executed", f"got {len(executions)}")

# --- GET task, GET tasks list, cross-user isolation ---
r4 = httpx.get(f"{BASE}/a2a/tasks/{task_id}", headers=HEADERS_A, timeout=15)
check(r4.status_code == 200 and r4.json()["id"] == task_id, "GET task by owner succeeds")

r5 = httpx.get(f"{BASE}/a2a/tasks/{task_id}", headers=HEADERS_B, timeout=15)
check(r5.status_code in (403, 404), "GET task by a different principal is denied", f"got {r5.status_code}")

r6 = httpx.get(f"{BASE}/a2a/tasks", headers=HEADERS_B, timeout=15)
check(r6.status_code == 200 and r6.json().get("tasks") == [], "outsider's task list is empty")

r7 = httpx.get(f"{BASE}/a2a/tasks", headers=HEADERS_A, timeout=15)
check(r7.status_code == 200 and any(t["id"] == task_id for t in r7.json().get("tasks", [])), "owner's task list includes their task")

# --- cancel on a terminal task should fail ---
r8 = httpx.post(f"{BASE}/a2a/tasks/{task_id}:cancel", headers=HEADERS_A, timeout=15)
check(r8.status_code == 409, "cancel on already-completed task -> 409", f"got {r8.status_code}")

print()
if failures:
    print(f"{len(failures)} FAILURE(S):", failures)
    raise SystemExit(1)
print("all checks passed")
