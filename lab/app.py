"""FastAPI application for MK-002 vulnerable lab.
This module exposes the HTTP surface of the lab. It is intentionally
minimal at MK-002 step 1: only /health exists. Auth, database and
vulnerable endpoints are added in later steps.
"""
from packaging import __title__
from fastapi import FastAPI

app = FastAPI(
    title = "MANTIS Lab",
    version = "1.0.0",
    description = "Local Vulnerable API lab for automated security testing"
)

@app.get("/health")
def health() -> dict[str, str]:
    """ Liveness probe.Public, local-onliy, no aunth."""
    return {"status": "ok"}
