"""Pure-logic unit tests for Q9 that don't touch Firestore."""
import base64
import sys

sys.path.insert(0, "..")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import q9_mailroom as m

failures = []


def check(cond, label):
    if not cond:
        failures.append(label)
    print(f"[{'OK' if cond else 'FAIL'}] {label}")


# canonical digest is order-independent on keys, order-dependent on arrays
d1 = {"b": 1, "a": [1, 2, 3]}
d2 = {"a": [1, 2, 3], "b": 1}
check(m.compute_input_digest([d1]) == m.compute_input_digest([d2]), "key order doesn't affect digest")

d3 = {"a": [3, 2, 1], "b": 1}
check(m.compute_input_digest([d1]) != m.compute_input_digest([d3]), "array order DOES affect digest")

# proposal digest: evidence order shouldn't matter (spec says sort before hashing)
p1 = {"dossierId": "d1", "callId": "c1", "action": "no_action", "target": None, "payload": {"x": 1}, "evidence": ["l2", "l1"]}
p2 = {"dossierId": "d1", "callId": "c1", "action": "no_action", "target": None, "payload": {"x": 1}, "evidence": ["l1", "l2"]}
check(m.compute_proposal_digest(p1) == m.compute_proposal_digest(p2), "proposal digest ignores evidence order")

# sanitize_decision: valid action passes through, invalid falls back safely
dossier = {
    "dossierId": "dX",
    "sources": [{"sourceId": "s1", "lines": [{"lineId": "l1", "text": "hello"}, {"lineId": "l2", "text": "world"}]}],
}
good = m.sanitize_decision(dossier, {"action": "no_action", "target": None, "payload": {"reasonCode": "DUPLICATE", "referenceId": "r1"}, "evidence": ["l1"]})
check(good["action"] == "no_action" and good["evidence"] == ["l1"], "sanitize passes through valid decision")

bad = m.sanitize_decision(dossier, {"action": "delete_everything", "payload": {}, "evidence": []})
check(bad["action"] == "request_confirmation", "sanitize falls back on invalid action")

unknown_evidence = m.sanitize_decision(dossier, {"action": "no_action", "target": None, "payload": {}, "evidence": ["l99"]})
check(unknown_evidence["evidence"] == ["l1"], "sanitize drops unknown lineIds and backfills a real one")

# Ed25519 signature verification round trip
priv = Ed25519PrivateKey.generate()
pub = priv.public_key()
pub_raw = pub.public_bytes_raw() if hasattr(pub, "public_bytes_raw") else pub.public_bytes(
    encoding=__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.Raw,
    format=__import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]).PublicFormat.Raw,
)
jwk = {"kty": "OKP", "crv": "Ed25519", "x": base64.urlsafe_b64encode(pub_raw).rstrip(b"=").decode()}

receipt_fields = {"dossierId": "d1", "callId": "c1", "action": "no_action", "accepted": True, "proposalDigest": "abc", "receiptId": "r1"}
message = m.canonical_json_bytes(receipt_fields)
sig = priv.sign(message)
receipt = dict(receipt_fields, receiptSignature=base64.b64encode(sig).decode())
check(m.verify_receipt_signature(jwk, receipt) is True, "valid Ed25519 signature verifies")

tampered = dict(receipt, accepted=False)
check(m.verify_receipt_signature(jwk, tampered) is False, "tampered receipt fails verification")

wrong_key_priv = Ed25519PrivateKey.generate()
wrong_sig = base64.b64encode(wrong_key_priv.sign(message)).decode()
check(m.verify_receipt_signature(jwk, dict(receipt, receiptSignature=wrong_sig)) is False, "signature from wrong key fails verification")

print()
if failures:
    print(f"{len(failures)} FAILURE(S):", failures)
    raise SystemExit(1)
print("all checks passed")
