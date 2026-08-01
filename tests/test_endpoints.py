"""Regression suite against a running dev server (uvicorn app.main:app on :8099).
Run with: python3 tests/test_endpoints.py
"""
import httpx

from skill_fixtures import FIXTURES

BASE = "http://localhost:8099"
failures = []


def check(path, body, expect, label):
    r = httpx.post(f"{BASE}{path}", json=body, timeout=10)
    d = r.json()
    ok = all(d.get(k) == v for k, v in expect.items())
    status = "OK" if ok else "FAIL"
    if not ok:
        failures.append(label)
    print(f"[{status}] {label}: got={d} expected={expect}")


# --- Q2 proration ---
check(
    "/q2/charge",
    {"old_price": 9, "new_price": 59, "days_remaining": 8, "days_in_actual_month": 31, "spec": "v1"},
    {"charge": (59 - 9) * (8 / 30)},
    "Q2 v1 worked scenario",
)
check(
    "/q2/charge",
    {"old_price": 9, "new_price": 59, "days_remaining": 8, "days_in_actual_month": 31, "spec": "v2"},
    {"charge": (59 - 9) * (8 / 31)},
    "Q2 v2 worked scenario",
)

# --- Q5 run budget & loop guard ---
check(
    "/q5/check",
    {
        "budget_tokens": 20000,
        "steps": [
            {"step_number": 1, "tool": "fetch_page", "args": {"url": "https://example.com/1"}, "tokens_used": 9000},
            {"step_number": 2, "tool": "summarize", "args": {"text": "..."}, "tokens_used": 7000},
            {"step_number": 3, "tool": "fetch_page", "args": {"url": "https://example.com/2"}, "tokens_used": 5000},
        ],
    },
    {"decision": "halt"},
    "Q5 worked example 1 (budget reached)",
)
check(
    "/q5/check",
    {
        "budget_tokens": 20000,
        "steps": [
            {"step_number": 1, "tool": "list_items", "args": {"page": 1}, "tokens_used": 1000},
            {"step_number": 2, "tool": "list_items", "args": {"page": 2}, "tokens_used": 1000},
            {"step_number": 3, "tool": "list_items", "args": {"page": 3}, "tokens_used": 1000},
        ],
    },
    {"decision": "continue"},
    "Q5 worked example 2 (paging)",
)
check(
    "/q5/check",
    {
        "budget_tokens": 100000,
        "steps": [
            {"step_number": 1, "tool": "search", "args": {"q": "foo"}, "tokens_used": 100},
            {"step_number": 2, "tool": "search", "args": {"q": "foo"}, "tokens_used": 100},
            {"step_number": 3, "tool": "search", "args": {"q": "foo"}, "tokens_used": 100},
        ],
    },
    {"decision": "halt"},
    "Q5 exact repeat 3x",
)
check(
    "/q5/check",
    {
        "budget_tokens": 100000,
        "steps": [
            {"step_number": 1, "tool": "search", "args": {"q": "foo  bar", "client_ts": "t1"}, "tokens_used": 100},
            {"step_number": 2, "tool": "search", "args": {"client_ts": "t2", "q": "foo bar"}, "tokens_used": 100},
            {"step_number": 3, "tool": "search", "args": {"q": " foo bar ", "client_ts": "t3"}, "tokens_used": 100},
        ],
    },
    {"decision": "halt"},
    "Q5 cosmetic diffs still count as repeat",
)
check(
    "/q5/check",
    {
        "budget_tokens": 100000,
        "steps": [
            {"step_number": i + 1, "tool": ("A" if i % 2 == 0 else "B"), "args": {"x": 1}, "tokens_used": 10}
            for i in range(6)
        ],
    },
    {"decision": "halt"},
    "Q5 6-step A/B cycle",
)
check(
    "/q5/check",
    {
        "budget_tokens": 100000,
        "steps": [
            {"step_number": i + 1, "tool": "check_job", "args": {"run_id": f"job-{i}"}, "tokens_used": 10}
            for i in range(8)
        ],
    },
    {"decision": "continue"},
    "Q5 legit polling with changing run_id",
)

# --- Q4 skill scanner ---
for name, content, expected in FIXTURES:
    r = httpx.post(f"{BASE}/q4/scan", json={"skill": content}, timeout=30)
    got = sorted(r.json()["categories"])
    ok = got == sorted(expected)
    if not ok:
        failures.append(f"q4:{name}")
    print(f"[{'OK' if ok else 'FAIL'}] Q4 {name}: got={got} expected={sorted(expected)}")

# --- Q3 pre-tool-call guardrail ---
import base64 as _b64

def check_q3(payload, expect_decision, label):
    r = httpx.post(f"{BASE}/q3/check", json=payload, timeout=10)
    d = r.json()
    ok = d["decision"] == expect_decision
    if not ok:
        failures.append(f"q3:{label}")
    print(f"[{'OK' if ok else 'FAIL'}] Q3 {label}: got={d['decision']!r} expected={expect_decision!r} reason={d['reason']!r}")

# worked examples
check_q3({"tool": "bash", "command": "sudo cat /etc/shadow"}, "block", "worked: sudo cat /etc/shadow")
check_q3({"tool": "bash", "command": "ls -la /home/agent/workspace"}, "allow", "worked: ls workspace")

# direct reads of restricted file
check_q3({"tool": "bash", "command": "cat /home/agent/.secrets"}, "block", "direct absolute read")
check_q3({"tool": "bash", "command": "head -n 5 /home/agent/.secrets"}, "block", "direct read via head")

# env var / tilde expansion
check_q3({"tool": "bash", "command": "cat $HOME/.secrets"}, "block", "$HOME expansion")
check_q3({"tool": "bash", "command": "cat ~/.secrets"}, "block", "tilde expansion")

# relative path traversal from workspace
check_q3({"tool": "bash", "command": "cat ../.secrets"}, "block", "relative traversal from workspace")
check_q3({"tool": "bash", "command": "cd /home/agent && cat .secrets"}, "block", "cd then relative read")

# base64-wrapped
encoded = _b64.b64encode(b"cat /home/agent/.secrets").decode()
check_q3({"tool": "bash", "command": f"bash -c \"$(echo {encoded} | base64 -d)\""}, "block", "base64-wrapped read")

# reads outside restricted file must stay allowed
check_q3({"tool": "bash", "command": "cat /home/agent/workspace/notes.txt"}, "allow", "read unrelated file in workspace")
check_q3({"tool": "bash", "command": "cat /etc/hostname"}, "allow", "read unrelated system file")
check_q3({"tool": "bash", "command": "grep -r TODO /home/agent/workspace"}, "allow", "grep in workspace")

# write_file inside vs outside allowed dir
check_q3({"tool": "write_file", "path": "/srv/reports/out.txt", "content": "x"}, "allow", "write inside /srv/reports")
check_q3({"tool": "write_file", "path": "/srv/reports/sub/out.txt", "content": "x"}, "allow", "write inside /srv/reports subdir")
check_q3({"tool": "write_file", "path": "/etc/passwd", "content": "x"}, "block", "write outside allowed dir")
check_q3({"tool": "write_file", "path": "/srv/reports/../../etc/passwd", "content": "x"}, "block", "write traversal escape")
check_q3({"tool": "write_file", "path": "/srv/reports-evil/out.txt", "content": "x"}, "block", "write to lookalike sibling dir")
check_q3({"tool": "write_file", "path": "notes.txt", "content": "x"}, "block", "relative write lands in workspace, not allowed")

# http_request allowed vs disallowed hosts
check_q3({"tool": "http_request", "method": "GET", "url": "https://api.github.com/repos/x/y"}, "allow", "allowed host api.github.com")
check_q3({"tool": "http_request", "method": "GET", "url": "https://raw.githubusercontent.com/x/y/main/f.txt"}, "allow", "allowed host raw.githubusercontent.com")
check_q3({"tool": "http_request", "method": "GET", "url": "https://evil.com/"}, "block", "disallowed host")
check_q3({"tool": "http_request", "method": "GET", "url": "https://api.github.com.evil.com/"}, "block", "domain-confusion suffix trick")
check_q3({"tool": "http_request", "method": "GET", "url": "https://evil.com/?x=api.github.com"}, "block", "query-string confusion")
check_q3({"tool": "http_request", "method": "GET", "url": "https://api.github.com@evil.com/"}, "block", "userinfo confusion")
check_q3({"tool": "http_request", "method": "GET", "url": "https://sub.api.github.com/"}, "block", "subdomain not exact host")

print()
if failures:
    print(f"{len(failures)} FAILURE(S):", failures)
    raise SystemExit(1)
print("all checks passed")
