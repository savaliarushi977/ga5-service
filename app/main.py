from fastapi import FastAPI

from . import q2_proration

app = FastAPI()

app.include_router(q2_proration.router)


@app.get("/")
def health():
    return {"ok": True}
