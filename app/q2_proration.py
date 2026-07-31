from fastapi import APIRouter
from pydantic import BaseModel
from typing import Literal

router = APIRouter()


class ProrationRequest(BaseModel):
    old_price: float
    new_price: float
    days_remaining: float
    days_in_actual_month: float
    spec: Literal["v1", "v2"]


class ProrationResponse(BaseModel):
    charge: float


@router.post("/q2/charge", response_model=ProrationResponse)
def charge(req: ProrationRequest):
    diff = req.new_price - req.old_price
    if req.spec == "v1":
        result = diff * (req.days_remaining / 30)
    else:
        result = diff * (req.days_remaining / req.days_in_actual_month)
    return ProrationResponse(charge=result)
