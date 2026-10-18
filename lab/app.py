"""FastAPI application for MK-002 vulnerable lab.
This module exposes the HTTP surface of the lab. It is intentionally
minimal at MK-002 step 1: only /health exists. Auth, database and
vulnerable endpoints are added in later steps.
"""
"""FastAPI application for the MANTIS local lab."""
from fastapi import FastAPI

from lab.routes import identity, invoices, lab

app = FastAPI(
    title="MANTIS Lab",
    version="0.1.0",
    description="Local vulnerable API lab for authorized security testing.",
)

app.include_router(identity.router)
app.include_router(invoices.router)
app.include_router(lab.router)


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness probe. Public, local-only, no auth."""
    return {"status": "ok"}
