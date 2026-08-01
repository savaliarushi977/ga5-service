from fastapi import FastAPI

from . import q2_proration, q3_guardrail, q4_scanner, q5_runguard, q8_redteam

app = FastAPI()

app.include_router(q2_proration.router)
app.include_router(q3_guardrail.router)
app.include_router(q4_scanner.router)
app.include_router(q5_runguard.router)
app.include_router(q8_redteam.router)


@app.get("/")
def health():
    return {"ok": True}
