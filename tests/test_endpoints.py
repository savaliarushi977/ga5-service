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

print()
if failures:
    print(f"{len(failures)} FAILURE(S):", failures)
    raise SystemExit(1)
print("all checks passed")
