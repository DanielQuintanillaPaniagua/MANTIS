"""BOLA detection (Broken Object Level Authorization).

Strategy:
1. Identify each identity's "scope" by calling /me (or alternatives).
2. Find GET operations with a path parameter (e.g. GET /invoices/{id}).
3. For each such operation:
   a. List resources with a privileged identity (or the first one).
   b. For each ID, compare the response for EACH identity.
   c. If an identity gets 200 AND the resource has an ownership field
      that does not match that identity's scope, report BOLA.

This module does NOT know V1 exists. It follows the generic rule:
"an identity accessing a resource it does not own is suspicious".
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from mantis.analysis.models import (
    Confidence,
    Evidence,
    Finding,
    FindingType,
    Severity,
)
from mantis.analysis.result import AssessmentState, ScanResult
from mantis.core.config import MantisConfig
from mantis.spec.models import ApiSpec, HttpMethod, Operation
from mantis.transport.client import MantisClient


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


def _assess_severity(method: HttpMethod, leaked_data: dict | None = None) -> Severity:
    """Assess the severity of a BOLA finding based on method and leaked data."""
    if method is HttpMethod.DELETE:
        return Severity.CRITICAL
    if method in (HttpMethod.PUT, HttpMethod.PATCH):
        return Severity.HIGH
    if leaked_data:
        sensitive_keywords = {"password", "token", "secret", "ssn", "credit_card", "api_key"}
        keys = {str(k).lower() for k in leaked_data.keys()}
        if keys & sensitive_keywords:
            return Severity.CRITICAL
    return Severity.HIGH


def detect_bola(
    spec: ApiSpec,
    client: MantisClient,
    config: MantisConfig,
    identities: list[Identity],
) -> ScanResult:
    """Detect BOLA across a matrix of identities."""
    if not identities:
        return ScanResult(state=AssessmentState.OMITTED, reason="No identities provided")

    scopes: dict[str, dict[str, str] | None] = {}
    for identity in identities:
        scopes[identity.name] = _resolve_scope(client, identity, config)

    lister = identities[0]
    lister_scope = scopes[lister.name]
    
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    used_fallback = False

    for op in spec.operations:
        if op.method is not HttpMethod.GET:
            continue
        path_param = _first_path_param(op)
        if path_param is None:
            continue

        parent_path = _parent_path(op.path)
        if parent_path is None:
            continue

        resource_ids = _list_resource_ids(client, lister, parent_path, config)
        if not resource_ids:
            resource_ids = [str(i) for i in FALLBACK_ID_RANGE]
            used_fallback = True

        for resource_id in resource_ids[:MAX_LISTED_RESOURCES]:
            for identity in identities:
                if identity.name == lister.name:
                    continue

                scope = scopes[identity.name]
                if scope is None:
                    continue

                key = (op.path, resource_id, identity.name)
                if key in seen:
                    continue
                seen.add(key)

                finding = _probe_resource(
                    client=client,
                    operation=op,
                    path_param=path_param,
                    resource_id=resource_id,
                    identity=lister,
                    identity_scope=lister_scope,
                    test_identity=identity,
                    test_scope=scope,
                    config=config,
                )
                if finding is not None:
                    findings.append(finding)

    if findings:
        return ScanResult(state=AssessmentState.CONFIRMED, findings=tuple(findings))
    
    if all(s is None for s in scopes.values()):
        return ScanResult(state=AssessmentState.INCONCLUSIVE, reason="Could not resolve scope for any identity")
        
    if used_fallback:
        return ScanResult(state=AssessmentState.INCONCLUSIVE, reason="Could not enumerate resources, used fallback IDs")
        
    return ScanResult(state=AssessmentState.NOT_FOUND)


def detect_bola_write(
    spec: ApiSpec,
    client: MantisClient,
    config: MantisConfig,
    identities: list[Identity],
) -> ScanResult:
    """Detect BOLA in write operations (PUT, PATCH, DELETE)."""
    if not config.reset_endpoint:
        return ScanResult(state=AssessmentState.OMITTED, reason="No reset_endpoint configured.")
    if not identities:
        return ScanResult(state=AssessmentState.OMITTED, reason="No identities provided")

    lister = identities[0]
    findings: list[Finding] = []

    for op in spec.operations:
        if op.method not in (HttpMethod.PUT, HttpMethod.PATCH, HttpMethod.DELETE):
            continue
        path_param = _first_path_param(op)
        if path_param is None:
            continue
        parent_path = _parent_path(op.path)
        if parent_path is None:
            continue
        read_path = _derive_read_path(op.path, path_param)
        if read_path is None:
            continue

        resource_ids = _list_resource_ids(client, lister, parent_path, config)
        if not resource_ids:
            continue

        for resource_id in resource_ids[:3]:
            if not _reset_lab(client, lister, config):
                return ScanResult(state=AssessmentState.INCONCLUSIVE, reason="Reset failed before write test.")

            url_read = lister.base_url.rstrip("/") + read_path.replace("{" + path_param + "}", resource_id)
            try:
                resp_init = client.get(url_read, headers=lister.headers())
                initial_state = resp_init.json()
            except Exception:
                continue

            for identity in identities[1:]:
                url_write = identity.base_url.rstrip("/") + op.path.replace("{" + path_param + "}", resource_id)
                payload = {"status": "hacked_by_mantis"} if op.method in (HttpMethod.PUT, HttpMethod.PATCH) else None

                try:
                    resp_write = client.request(
                        op.method.value, 
                        url_write, 
                        headers=identity.headers(),
                        json=payload
                    )
                except httpx.HTTPError:
                    continue

                if resp_write.status_code in (200, 201, 204):
                    # Intentar restaurar
                    reset_ok = _reset_lab(client, lister, config)
                    restored = False
                    if reset_ok:
                        restored = _verify_state(client, lister, read_path, path_param, resource_id, initial_state, config)
                    
                    if not restored:
                        return ScanResult(
                            state=AssessmentState.INCONCLUSIVE,
                            reason=f"Could not restore state after {op.method.value} on resource {resource_id}. Aborting."
                        )

                    findings.append(
                        Finding(
                            id=f"BOLA-{op.method.value}-{op.path.replace('/', '_')}-{resource_id}-{identity.name}",
                            type=FindingType.BOLA,
                            severity=_assess_severity(op.method, initial_state),
                            confidence=Confidence.HIGH,
                            operation_method=op.method.value,
                            operation_path=op.path,
                            identity=identity.name,
                            summary=f"{identity.name} could {op.method.value} resource {resource_id}",
                            details=f"Identity '{identity.name}' executed {op.method.value} {op.path} on resource {resource_id} and received {resp_write.status_code}.",
                            evidence=(
                                Evidence(description="Read initial state", method="GET", url=url_read, status=200),
                                Evidence(description=f"Unauthorized {op.method.value}", method=op.method.value, url=url_write, status=resp_write.status_code),
                            ),
                            reproduction=(
                                f"1. Reset lab",
                                f"2. As {identity.name}, execute {op.method.value} {url_write}",
                                f"3. Expected 403, got {resp_write.status_code}"
                            )
                        )
                    )
                    break 

    if findings:
        return ScanResult(state=AssessmentState.CONFIRMED, findings=tuple(findings))
    return ScanResult(state=AssessmentState.NOT_FOUND)


def _resolve_scope(
    client: MantisClient, identity: Identity, config: MantisConfig
) -> dict[str, str] | None:
    for path in config.identity_endpoints:
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


def _verify_state(
    client: MantisClient,
    identity: Identity,
    read_path: str,
    path_param: str,
    resource_id: str,
    expected_state: dict[str, str],
    config: MantisConfig,
) -> bool:
    url = identity.base_url.rstrip("/") + read_path.replace("{" + path_param + "}", resource_id)
    try:
        response = client.get(url, headers=identity.headers())
    except httpx.HTTPError:
        return False
    if response.status_code != 200:
        return False
    try:
        data = response.json()
    except ValueError:
        return False
    for field, expected_value in expected_state.items():
        if field in data and str(data[field]) != expected_value:
            return False
    return True


def _first_path_param(op: Operation) -> str | None:
    for p in op.parameters:
        if p.location.value == "path":
            return p.name
    return None


def _parent_path(path: str) -> str | None:
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
        if isinstance(item, dict) and config.resource_id_field in item:
            ids.append(str(item[config.resource_id_field]))
    return ids


def _reset_lab(client: MantisClient, identity: Identity, config: MantisConfig) -> bool:
    if not config.reset_endpoint:
        return False
    url = identity.base_url.rstrip("/") + config.reset_endpoint
    try:
        response = client.post(url, headers=identity.headers())
    except httpx.HTTPError:
        return False
    return response.status_code in (200, 204)


def _probe_resource(
    *,
    client: MantisClient,
    operation: Operation,
    path_param: str,
    resource_id: str,
    identity: Identity,
    identity_scope: dict[str, str] | None,
    test_identity: Identity,
    test_scope: dict[str, str],
    config: MantisConfig,
) -> Finding | None:
    url_lister = _build_url(identity.base_url, operation.path, path_param, resource_id)
    url_test = _build_url(test_identity.base_url, operation.path, path_param, resource_id)

    try:
        response_lister = client.get(url_lister, headers=identity.headers())
    except httpx.HTTPError:
        return None
    if response_lister.status_code != 200:
        return None

    try:
        response_test = client.get(url_test, headers=test_identity.headers())
    except httpx.HTTPError:
        return None
    if response_test.status_code != 200:
        return None

    try:
        body_test = response_test.json()
    except ValueError:
        return None
    if not isinstance(body_test, dict):
        return None

    mismatches = []
    for field, scope_value in test_scope.items():
        if field in body_test and body_test[field] is not None:
            resource_value = str(body_test[field])
            if resource_value != scope_value:
                mismatches.append((field, scope_value, resource_value))

    if not mismatches:
        return None

    evidence = (
        Evidence(
            description=f"{identity.name} reads resource {resource_id}",
            method="GET",
            url=url_lister,
            status=response_lister.status_code,
            response_size=len(response_lister.content),
        ),
        Evidence(
            description=f"{test_identity.name} reads resource {resource_id}",
            method="GET",
            url=url_test,
            status=response_test.status_code,
            response_size=len(response_test.content),
        ),
    )

    mismatch_desc = ", ".join(f"{f}: {i} vs {r}" for f, i, r in mismatches)

    return Finding(
        id=f"BOLA-{operation.path.replace('/', '_')}-{resource_id}-{test_identity.name}",
        type=FindingType.BOLA,
        severity=_assess_severity(operation.method, body_test),
        confidence=Confidence.HIGH,
        operation_method=operation.method.value,
        operation_path=operation.path,
        identity=test_identity.name,
        summary=f"{test_identity.name} can access resource {resource_id} outside its scope ({mismatch_desc})",
        details=(
            f"Identity '{test_identity.name}' (scope: {test_scope}) accessed resource '{resource_id}' "
            f"via {operation.method.value} {operation.path}. Expected 403, got 200. "
            f"Ownership mismatch ({mismatch_desc})."
        ),
        evidence=evidence,
        reproduction=(
            f"1. Use identity '{test_identity.name}'",
            f"2. GET {url_test}",
            f"3. Expected 403, got {response_test.status_code}",
        ),
    )


def _build_url(base_url: str, path: str, param: str, value: str) -> str:
    return base_url.rstrip("/") + path.replace("{" + param + "}", value)
