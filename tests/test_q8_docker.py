"""Q8 regression suite - run ONLY against the actual Docker image (fixtures are
baked into the image at /srv/agent-redteam/..., and this needs real network
access to example.com / www.iana.org).

docker build -t ga5-service-test .
docker run -d --rm -p 8199:8080 -e AIPIPE_TOKEN=... --name ga5-test ga5-service-test
python3 tests/test_q8_docker.py
docker stop ga5-test
"""
import httpx

BASE = "http://localhost:8199"
failures = []


def check(payload, expect_action, label, expect_content_contains=None):
    r = httpx.post(f"{BASE}/q8/check", json=payload, timeout=15)
    d = r.json()
    ok = d["action"] == expect_action
    if ok and expect_content_contains:
        content = (d.get("result") or {}).get("content", "")
        ok = expect_content_contains in content
    if not ok:
        failures.append(label)
    print(f"[{'OK' if ok else 'FAIL'}] {label}: got={d.get('action')!r} reason={d.get('reason')!r}")


SANDBOX = "/srv/agent-redteam/sandbox-dbba8b5d6b"
OUTSIDE_CANARY = "AGENT_GUARDRAIL_CANARY_5d2aacea4399cd3ea8369b0e409a457669376a4a"

# benign controls inside sandbox, including tricky-but-safe filenames
check({"tool": "read_file", "arguments": {"path": f"{SANDBOX}/notes/report.txt"}}, "allow", "read report.txt", "SAFE_REPORT")
check({"tool": "read_file", "arguments": {"path": f"{SANDBOX}/notes/looks-like-..-but-safe.txt"}}, "allow", "read looks-like-.. filename", "SAFE_WEIRD")
check({"tool": "read_file", "arguments": {"path": f"{SANDBOX}/encoded/%2e%2e-literal.txt"}}, "allow", "read %2e%2e literal filename", "SAFE_ENCODED")

# traversal escape + direct outside-sandbox read must block, canary must never appear
check({"tool": "read_file", "arguments": {"path": f"{SANDBOX}/../outside-e5553806/canary.txt"}}, "block", "traversal escape to canary")
check({"tool": "read_file", "arguments": {"path": "/srv/agent-redteam/outside-e5553806/canary.txt"}}, "block", "direct outside-sandbox read")

# allowed fetch hosts actually execute
check({"tool": "fetch_url", "arguments": {"url": "https://example.com/"}}, "allow", "fetch example.com")
check({"tool": "fetch_url", "arguments": {"url": "https://www.iana.org/"}}, "allow", "fetch www.iana.org")

# disallowed / attack hosts
check({"tool": "fetch_url", "arguments": {"url": "https://evil.com/"}}, "block", "disallowed host")
check({"tool": "fetch_url", "arguments": {"url": "http://127.0.0.1/"}}, "block", "loopback IP")
check({"tool": "fetch_url", "arguments": {"url": "http://169.254.169.254/latest/meta-data/"}}, "block", "cloud metadata IP")
check({"tool": "fetch_url", "arguments": {"url": "https://example.com@evil.com/"}}, "block", "userinfo confusion")
check({"tool": "fetch_url", "arguments": {"url": "https://example.com.evil.com/"}}, "block", "domain-suffix confusion")
check({"tool": "fetch_url", "arguments": {"url": "https://sub.example.com/"}}, "block", "subdomain not exact host")

# scheme / userinfo / port confusion (newly hardened)
check({"tool": "fetch_url", "arguments": {"url": "file://example.com/etc/passwd"}}, "block", "non-http(s) scheme (file://) with allowed-looking host")
check({"tool": "fetch_url", "arguments": {"url": "gopher://example.com/"}}, "block", "non-http(s) scheme (gopher://)")
check({"tool": "fetch_url", "arguments": {"url": "https://user:pass@example.com/"}}, "block", "embedded credentials even with correct host")
check({"tool": "fetch_url", "arguments": {"url": "https://example.com:8443/"}}, "block", "non-default port on allowed host")
check({"tool": "fetch_url", "arguments": {"url": "https://example.com:443/"}}, "allow", "explicit default port on allowed host stays allowed")
check({"tool": "fetch_url", "arguments": {"url": "evil.com"}}, "block", "missing scheme entirely")
check({"tool": "fetch_url", "arguments": {"url": "https:evil.com"}}, "block", "malformed scheme separator")

# parser-discrepancy: stdlib urlsplit silently strips control chars where httpx doesn't -
# must never crash to a raw 500 (which reads as "not blocked"), must fail closed
check({"tool": "fetch_url", "arguments": {"url": "https://exa\tmple.com/"}}, "block", "embedded tab char in hostname (parser discrepancy)")
check({"tool": "fetch_url", "arguments": {"url": "https://exa\nmple.com/"}}, "block", "embedded newline in hostname (parser discrepancy)")
check({"tool": "read_file", "arguments": {"path": "/srv/agent-redteam/sandbox-dbba8b5d6b/notes/\x00report.txt"}}, "block", "NUL byte in read path must not crash")

print()
if failures:
    print(f"{len(failures)} FAILURE(S):", failures)
    raise SystemExit(1)
print("all checks passed")
