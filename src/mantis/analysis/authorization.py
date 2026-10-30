"""BOLA detection (Broken Object Level Authorization).

Strategy:
1. Identify each identity's "scope" by calling /me (or /users/me, /profile).
2. Find GET operations with a path parameter (e.g. GET /invoices/{id}).
3. For each such operation:
   a. List resources with identity A (admin) to get IDs.
   b. For each ID, compare responses of A and B.
   c. If B gets 200 AND the resource has an ownership field that
      does not match B's scope, report a BOLA finding.

This module does NOT know V1 exists. It follows the generic rule:
"an identity accessing a resource it does not own is suspicious".
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from mantis.analysis.models import(
    Confidence,
    Evidence,
    Finding,
    FindingType,
    Severity,
)
from mantis.core.config import MantisConfig
from mantis.spec.models import ApiSpec, HttpMethod,Operation
from mantis.transport.client import MantisClient

IDENTITY_ENDPOINTS = ("/me", "/users/me", "/profile")
MAX_LISTED_RESOURCES = 20
FALLBACK_ID_RANGE = range(1, 11)


@dataclass(frozen=True)
class Identity:
    """A named identity with an API key."""

    name: str
    api_key: str
    base_url: str

    def headers(self) -> dict[str, str]:
        return {"X-API-Key": self.api_key}


def detect_bola(
    spec: ApiSpec,
    client: MantisClient,
    config: MantisConfig,
    identity_a: Identity,
    identity_b: Identity,
) -> tuple[Finding, ...]:
    """Detect BOLA between two identities.

    Identity A is the "privileged" identity (admin).
    Identity B is the "limited" identity (employee).

    Returns findings. Empty tuple means "nothing detected".
    """
    scope_a = _resolve_scope(client, identity_a, config)
    scope_b = _resolve_scope(client, identity_b, config)

    if scope_b is None:
        # Without B's scope we cannot determine ownership.
        return ()

    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    for op in spec.operations:
        if op.method is not HttpMethod.GET:
            continue
        path_param = _first_path_param(op)
        if path_param is None:
            continue

        parent_path = _parent_path(op.path)
        if parent_path is None:
            continue

        resource_ids = _list_resource_ids(client, identity_a, parent_path, config)
        if not resource_ids:
            resource_ids = [str(i) for i in FALLBACK_ID_RANGE]

        for resource_id in resource_ids[:MAX_LISTED_RESOURCES]:
            key = (op.path, resource_id)
            if key in seen:
                continue
            seen.add(key)

            finding = _probe_resource(
                client=client,
                operation=op,
                path_param=path_param,
                resource_id=resource_id,
                identity_a=identity_a,
                identity_b=identity_b,
                scope_b=scope_b,
                config=config,
            )
            if finding is not None:
                findings.append(finding)

    return tuple(findings)


def _resolve_scope(
    client: MantisClient, identity: Identity, config: MantisConfig
) -> dict[str, str] | None:
    """Call /me (or alternatives) and extract ownership fields.

    Returns a dict of {field: value} for any ownership_fields present
    in the response. None if /me cannot be resolved.
    """
    for path in IDENTITY_ENDPOINTS:
        url = identity.base_url.rstrip("/") + path
        try:
            response = client.get(url, headers=identity.headers())
        except httpx.HTTPError:
            continue
        if response.status_code != 200:
            continue
        try:
            data = response.json()
        except ValueError:
            continue
        if not isinstance(data, dict):
            continue
        scope = {
            field: str(data[field])
            for field in config.ownership_fields
            if field in data and data[field] is not None
        }
        if scope:
            return scope
    return None


def _first_path_param(op: Operation) -> str | None:
    for p in op.parameters:
        if p.location.value == "path":
            return p.name
    return None


def _parent_path(path: str) -> str | None:
    """Derive the listing path: /invoices/{id} -> /invoices."""
    if "{" not in path:
        return None
    parent = path.split("/{", 1)[0]
    return parent if parent else None


def _list_resource_ids(
    client: MantisClient,
    identity: Identity,
    parent_path: str,
    config: MantisConfig,
) -> list[str]:
    """List resources at the parent path and extract IDs."""
    url = identity.base_url.rstrip("/") + parent_path
    try:
        response = client.get(url, headers=identity.headers())
    except httpx.HTTPError:
        return []
    if response.status_code != 200:
        return []
    try:
        data = response.json()
    except ValueError:
        return []
    if not isinstance(data, list):
        return []
    ids: list[str] = []
    for item in data:
        if isinstance(item, dict) and "id" in item:
            ids.append(str(item["id"]))
    return ids


def _probe_resource(
    *,
    client: MantisClient,
    operation: Operation,
    path_param: str,
    resource_id: str,
    identity_a: Identity,
    identity_b: Identity,
    scope_b: dict[str, str],
    config: MantisConfig,
) -> Finding | None:
    """Probe one resource with both identities. Return a finding if BOLA detected."""
    url_a = _build_url(identity_a.base_url, operation.path, path_param, resource_id)
    url_b = _build_url(identity_b.base_url, operation.path, path_param, resource_id)

    try:
        response_a = client.get(url_a, headers=identity_a.headers())
    except httpx.HTTPError:
        return None

    if response_a.status_code != 200:
        return None

    try:
        response_b = client.get(url_b, headers=identity_b.headers())
    except httpx.HTTPError:
        return None

    if response_b.status_code != 200:
        return None

    try:
        body_b = response_b.json()
    except ValueError:
        return None

    if not isinstance(body_b, dict):
        return None

    mismatches = []
    for field, scope_value in scope_b.items():
        if field in body_b and body_b[field] is not None:
            resource_value = str(body_b[field])
            if resource_value != scope_value:
                mismatches.append((field, scope_value, resource_value))

    if not mismatches:
        return None

    evidence = (
        Evidence(
            description=f"{identity_a.name} reads resource {resource_id}",
            method="GET",
            url=url_a,
            status=response_a.status_code,
            response_size=len(response_a.content),
        ),
        Evidence(
            description=f"{identity_b.name} reads resource {resource_id}",
            method="GET",
            url=url_b,
            status=response_b.status_code,
            response_size=len(response_b.content),
        ),
    )

    mismatch_desc = ", ".join(
        f"{field}: {ident_val} vs {res_val}"
        for field, ident_val, res_val in mismatches
    )

    return Finding(
        id=f"BOLA-{operation.path.replace('/', '_')}-{resource_id}",
        type=FindingType.BOLA,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        operation_method=operation.method.value,
        operation_path=operation.path,
        identity=identity_b.name,
        summary=(
            f"{identity_b.name} can access resource {resource_id} "
            f"outside its scope ({mismatch_desc})"
        ),
        details=(
            f"Identity '{identity_b.name}' (scope: {scope_b}) accessed "
            f"resource '{resource_id}' via {operation.method.value} {operation.path}. "
            f"The resource's ownership fields do not match: {mismatch_desc}. "
            f"Expected 403, got 200."
        ),
        evidence=evidence,
        reproduction=(
            f"1. Use identity '{identity_b.name}' (API key: {identity_b.api_key[:8]}...)",
            f"2. GET {url_b}",
            f"3. Expected 403 (resource outside scope), got {response_b.status_code}",
            f"4. Compare with identity '{identity_a.name}' on same URL: {response_a.status_code}",
        ),
    )


def _build_url(base_url: str, path: str, param: str, value: str) -> str:
    return base_url.rstrip("/") + path.replace("{" + param + "}", value)