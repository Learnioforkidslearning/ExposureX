"""ExposureX API. Run from the backend folder: uvicorn main:app --reload"""
import os, re
from datetime import datetime, timezone
import httpx
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from services import DEMO, risk_score, recommendations, analyse_url

XON = os.getenv("XON_BASE_URL", "https://api.xposedornot.com")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
app = FastAPI(title="ExposureX")

class ScanReq(BaseModel):
    email: str
    demo: bool = False
    practices: dict | None = None

class UrlReq(BaseModel):
    url: str

def parse_analytics(data):
    """Map XposedOrNot breach-analytics JSON to our schema (field names UNVERIFIED: check live docs)."""
    details = (data.get("ExposedBreaches") or {}).get("breaches_details") or []
    return [dict(breach=d.get("breach"), domain=d.get("domain"), date=str(d.get("xposed_date") or ""),
                 data=[x.strip() for x in str(d.get("xposed_data") or "").split(";") if x.strip()]) for d in details]

@app.get("/api/health")
def health(): return {"status": "ok"}

@app.post("/api/scan")
async def scan(req: ScanReq):
    email = req.email.strip().lower()
    if not EMAIL_RE.match(email): raise HTTPException(422, "Enter a valid email address.")
    stamp = datetime.now(timezone.utc).isoformat()
    if req.demo:
        b, status, src = DEMO, "exposure_found", "SAMPLE DEMO DATA (not a real lookup)"
    else:
        src = "XposedOrNot"
        try:
            async with httpx.AsyncClient(timeout=12) as c:
                r = await c.get(f"{XON}/v1/breach-analytics", params={"email": email})
        except httpx.HTTPError:
            return {"status": "unable_to_assess", "message": "Provider unreachable or timed out. Retry or use demo mode.", "source": src, "scanned_at": stamp}
        if r.status_code == 404: b, status = [], "no_known_match"
        elif r.status_code == 429: return {"status": "unable_to_assess", "message": "Provider rate limit reached. Wait and retry.", "source": src, "scanned_at": stamp}
        elif r.status_code != 200: return {"status": "unable_to_assess", "message": f"Provider returned HTTP {r.status_code}.", "source": src, "scanned_at": stamp}
        else:
            b = parse_analytics(r.json()); status = "exposure_found" if b else "no_known_match"
    score, level, factors = risk_score(b, req.practices)
    orgs = {(x.get("domain") or x["breach"]).lower() for x in b}
    return dict(status=status, incidents=len(b), unique_organisations=len(orgs), breaches=b, score=score, level=level,
                factors=factors, recommendations=recommendations(b, req.practices), source=src, scanned_at=stamp,
                disclaimer="A clean result does not guarantee safety. The score is a project-defined heuristic, not a probability.")

@app.post("/api/url-check")
def url_check(req: UrlReq): return analyse_url(req.url)

# Serves the frontend at / (same origin, so no CORS setup needed). Keep this LAST.
app.mount("/", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "..", "frontend"), html=True), name="fe")
