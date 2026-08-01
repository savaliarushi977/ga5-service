"""Force a cache-miss batch (fresh dossier content + larger than one chunk) to
verify the new chunked/parallel LLM path and deterministic payload construction."""
import sys
import time
import uuid

import httpx

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://ga5-service-101117070908.asia-south1.run.app"
URL = f"{BASE}/q9/mailroom"

unique = uuid.uuid4().hex[:8]


def make_dossier(did, mailbox, objective, lines):
    return {
        "dossierId": did,
        "partition": "stable_core",
        "receivedAt": "2026-08-01T00:00:00Z",
        "mailbox": mailbox,
        "objective": objective,
        "sources": [{
            "sourceId": f"{did}-src", "kind": "email", "provenance": "external", "title": objective,
            "lines": [{"lineId": f"{did}-l{i}", "text": t} for i, t in enumerate(lines)],
        }],
    }


# 14 dossiers (forces 3 chunks at CHUNK_SIZE=6) with fresh unique content
DOSSIERS = []
for i in range(14):
    did = f"fresh-{unique}-{i}"
    DOSSIERS.append(make_dossier(
        did, "orders", f"Order status request #{i}",
        [f"From: customer{i}@example.com", f"Please give me the status of order REF-{2000+i}.", f"Order reference REF-{2000+i}, delivered to customer{i}@example.com."],
    ))

eval_id = f"eval-fresh-{unique}"
req = {
    "operation": "propose",
    "evaluationId": eval_id,
    "receiptVerifier": {"algorithm": "Ed25519", "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
    "dossiers": DOSSIERS,
}

start = time.time()
r = httpx.post(URL, json=req, timeout=60)
elapsed = time.time() - start
print(f"status={r.status_code} elapsed={elapsed:.1f}s")
if r.status_code != 200:
    print(r.text[:500])
    raise SystemExit(1)

proposals = r.json()["proposals"]
print(f"got {len(proposals)} proposals")
fails = []
for p in proposals:
    ok = p["action"] == "create_draft" and p.get("target", {}).get("kind") == "draft_queue" and p.get("payload", {}).get("template") == "order_status"
    print(f"  {p['dossierId']}: action={p['action']} target={p.get('target')} payload={p.get('payload')}")
    if not ok:
        fails.append(p["dossierId"])

if fails:
    print("FAILURES:", fails)
    raise SystemExit(1)
if elapsed > 55:
    print(f"WARNING: took {elapsed:.1f}s, exceeds the 55s per-request budget")
    raise SystemExit(1)
print("all fresh-batch checks passed, well within time budget")
