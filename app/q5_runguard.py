import re
from typing import Literal, Any

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class Step(BaseModel):
    step_number: int
    tool: str
    args: dict
    tokens_used: int


class RunGuardRequest(BaseModel):
    budget_tokens: int
    steps: list[Step]


class RunGuardResponse(BaseModel):
    decision: Literal["continue", "halt"]
    reason: str


def canon(obj: Any) -> Any:
    """Canonicalize a JSON-like value for functional-identity comparison:
    drop any field literally named client_ts, ignore key order (dict equality
    already does this), and collapse whitespace-only differences in strings."""
    if isinstance(obj, dict):
        return {
            k: canon(v) for k, v in obj.items() if k != "client_ts"
        }
    if isinstance(obj, list):
        return [canon(v) for v in obj]
    if isinstance(obj, str):
        return re.sub(r"\s+", " ", obj.strip())
    return obj


def step_key(step: Step):
    return (step.tool, canon(step.args))


def trailing_exact_repeat(steps: list[Step]) -> bool:
    if len(steps) < 3:
        return False
    last_key = step_key(steps[-1])
    count = 0
    for s in reversed(steps):
        if step_key(s) == last_key:
            count += 1
        else:
            break
    return count >= 3


def trailing_two_cycle(steps: list[Step]) -> bool:
    n = len(steps)
    if n < 6:
        return False
    keys = [step_key(s) for s in steps]
    x, y = keys[-1], keys[-2]
    if x == y:
        return False  # that's the exact-repeat case, not a distinct A/B cycle
    length = 0
    for pos in range(1, n + 1):
        key = keys[-pos]
        expected = x if pos % 2 == 1 else y
        if key != expected:
            break
        length += 1
    return length >= 6


@router.post("/q5/check", response_model=RunGuardResponse)
def check(req: RunGuardRequest):
    total_tokens = sum(s.tokens_used for s in req.steps)
    if total_tokens >= req.budget_tokens:
        return RunGuardResponse(
            decision="halt",
            reason=f"Cumulative tokens_used ({total_tokens}) has reached the budget ({req.budget_tokens}).",
        )

    if trailing_exact_repeat(req.steps):
        return RunGuardResponse(
            decision="halt",
            reason="The same tool was called 3 or more times in a row with functionally identical arguments.",
        )

    if trailing_two_cycle(req.steps):
        return RunGuardResponse(
            decision="halt",
            reason="Trailing steps show a 2-step A/B cycle repeating for 6 or more steps.",
        )

    return RunGuardResponse(
        decision="continue",
        reason="Well under budget with no repeated-call loop or cycle detected.",
    )
