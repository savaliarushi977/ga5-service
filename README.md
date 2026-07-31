# GA5 Service

Consolidated FastAPI service hosting several GA5 endpoints as separate routes
on one Cloud Run deployment.

## Routes

- `POST /q2/charge` — proration calculator (spec v1/v2)

## Local dev

```
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Deploy (Cloud Run)

```
gcloud run deploy ga5-service --source . --region asia-south1 --allow-unauthenticated
```
