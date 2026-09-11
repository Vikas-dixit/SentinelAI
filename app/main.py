from fastapi import FastAPI

from app.detector import analyze_event
from app.models import SecurityEvent

app = FastAPI(
    title="SentinelAI",
    description="AI-ready personal SOC API for defensive security monitoring",
    version="0.1.0",
)


@app.get("/")
def root():
    return {
        "name": "SentinelAI",
        "status": "running",
        "message": "Personal SOC API is online",
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze")
def analyze(event: SecurityEvent):
    return analyze_event(event.model_dump())
