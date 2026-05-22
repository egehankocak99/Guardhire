from __future__ import annotations

import sys
import os

_ROOT = os.path.dirname(os.path.dirname(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from api.routes import audit, health, questions, screen

app = FastAPI(
    title="GuardHire",
    description="AI-powered hiring assistant with bias detection, PII redaction, and EU AI Act compliance.",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

_ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(health.router, tags=["Health"])
app.include_router(screen.router, tags=["CV Screening"])
app.include_router(questions.router, tags=["Interview Questions"])
app.include_router(audit.router, tags=["Audit"])

_FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.isdir(_FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=_FRONTEND_DIR, html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
