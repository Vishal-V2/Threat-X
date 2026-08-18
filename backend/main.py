"""Threat-X FastAPI application entrypoint."""
from __future__ import annotations

import os
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.routes import findings, scans, tickets
from backend.schemas import HealthResponse

load_dotenv()

app = FastAPI(
    title="Threat-X API",
    version="1.0.0",
    description="REST API adapter for Threat-X Risk Prioritization Platform",
)

# CORS configuration
allowed_origins_env = os.environ.get("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000")
allowed_origins = [orig.strip() for orig in allowed_origins_env.split(",") if orig.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health", response_model=HealthResponse, tags=["health"])
def health_check():
    return HealthResponse(status="ok")


# Include routers
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(tickets.router)
