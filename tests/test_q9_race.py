"""Fire two concurrent propose() calls for the SAME evaluationId but DIFFERENT
content - exactly the race the atomic .create() claim is meant to close."""
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor

import httpx

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://ga5-service-101117070908.asia-south1.run.app"
URL = f"{BASE}/q9/mailroom"


def make_dossier(did, text_suffix):
    return {
        "dossierId": did, "partition": "stable_core", "receivedAt": "2026-08-01T00:00:00Z",
        "mailbox": "orders", "objective": "test",
        "sources": [{"sourceId": f"{did}-src", "kind": "email", "provenance": "external", "title": "t",
            "lines": [{"lineId": f"{did}-l0", "text": f"Order status request {text_suffix}"}]}],
    }


eval_id = f"eval-race-{uuid.uuid4().hex}"
jwk = {"kty": "OKP", "crv": "Ed25519", "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}

req_a = {"operation": "propose", "evaluationId": eval_id, "receiptVerifier": {"algorithm": "Ed25519", "publicKeyJwk": jwk},
         "dossiers": [make_dossier("d1", "variant-A")]}
req_b = {"operation": "propose", "evaluationId": eval_id, "receiptVerifier": {"algorithm": "Ed25519", "publicKeyJwk": jwk},
         "dossiers": [make_dossier("d1", "variant-B")]}  # different content, same evaluationId


def fire(req):
    return httpx.post(URL, json=req, timeout=60)


with ThreadPoolExecutor(max_workers=2) as pool:
    fa = pool.submit(fire, req_a)
    fb = pool.submit(fire, req_b)
    ra = fa.result()
    rb = fb.result()

statuses = sorted([ra.status_code, rb.status_code])
print(f"response A: {ra.status_code} {ra.text[:150]}")
print(f"response B: {rb.status_code} {rb.text[:150]}")

# Exactly one should succeed (200) and the other should see the conflict (409) -
# never both 200 (that would mean the race let a different-content propose through).
ok = statuses == [200, 409]
print(f"[{'OK' if ok else 'FAIL'}] exactly one 200 and one 409, got statuses={statuses}")
raise SystemExit(0 if ok else 1)
