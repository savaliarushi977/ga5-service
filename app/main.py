from fastapi import FastAPI

from . import q2_proration, q3_guardrail, q4_scanner, q5_runguard, q8_redteam, q9_mailroom, q10_a2a, q11_incident

app = FastAPI()

app.include_router(q2_proration.router)
app.include_router(q3_guardrail.router)
app.include_router(q4_scanner.router)
app.include_router(q5_runguard.router)
app.include_router(q8_redteam.router)
app.include_router(q9_mailroom.router)
app.include_router(q10_a2a.router)
app.include_router(q11_incident.router)


@app.middleware("http")
async def a2a_content_type_middleware(request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/a2a/"):
        response.headers["Content-Type"] = "application/a2a+json"
    return response


@app.get("/")
def health():
    return {"ok": True}
