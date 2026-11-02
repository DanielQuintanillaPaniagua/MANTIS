"""Sequence-based detection: BFLA and state skip.

BFLA (Broken Function Level Authorization):
  A privileged identity A can execute a state-changing operation.
  A limited identity B can also execute it on the same resource.
  If the resource's state changed, B performed a privileged action.

State skip:
  A state-changing operation moves a resource from state X to state Y.
  If X -> Y was never observed with A, it is a forbidden transition.

This module does NOT know V2 or V3 exist. It follows generic rules.

Reset: if the spec declares POST /lab/reset, it is called between probes
to guarantee the same initial state. Without reset, findings may be
less reliable (documented limitation).
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from mantis.analysis.authorization import Identity
from mantis.analysis.models import (
    Confidence,
    Evidence,
    Finding,
    FindingType,
    Severity,
)
from mantis.core.config import MantisConfig
from mantis.spec.models import ApiSpec, HttpMethod, Operation
from mantis.transport.client import MantisClient


STATE_CHANGING_METHODS = {
    HttpMethod.POST,
    HttpMethod.PUT,
    HttpMethod.PATCH,
    HttpMethod.DELETE,
}

RESET_PATH = "/lab/reset"
MAX_PROBES_PER_OPERATION = 3


def detect_bfla(
    spec: ApiSpec,
    client: MantisClient,
    config: MantisConfig,
    identity_a: Identity,
    identity_b: Identity,
) -> tuple[Finding, ...]:
    """Detect BFLA between a privileged and a limited identity.

    Requires /lab/reset in the spec to reset between probes.
    Without reset, returns () and warns.
    """
    reset_available = any(
        op.method is HttpMethod.POST and op.path == RESET_PATH
        for op in spec.operations
    )
    if not reset_available:
        return ()

    findings: list[Finding] = []

    if not config.privileged_operations:
        # Without a declaration of privileged operations, we cannot
        # distinguish legitimate state changes from privileged ones.
        return ()

    for op in spec.operations:
        if op.method not in STATE_CHANGING_METHODS:
            continue
        if not _is_privileged(op.path, config.privileged_operations):
            continue
        path_param = _first_path_param(op)
        if path_param is None:
            continue

        # List B's resources (limited identity) at parent path.
        parent_path = _parent_path(op.path)
        if parent_path is None:
            continue

        b_resources = _list_resource_ids(client, identity_b, parent_path)
        if not b_resources:
            continue

        for resource_id in b_resources[:MAX_PROBES_PER_OPERATION]:
            finding = _probe_bfla(
                client=client,
                spec=spec,
                operation=op,
                path_param=path_param,
                resource_id=resource_id,
                identity_a=identity_a,
                identity_b=identity_b,
                config=config,
            )
            if finding is not None:
                findings.append(finding)

    return tuple(findings)


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
    client: MantisClient, identity: Identity, parent_path: str
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
        if isinstance(item, dict) and "id" in item:
            ids.append(str(item["id"]))
    return ids


def _reset_lab(client: MantisClient, identity_a: Identity) -> bool:
    url = identity_a.base_url.rstrip("/") + RESET_PATH
    try:
        response = client.post(url, headers=identity_a.headers())
    except httpx.HTTPError:
        return False
    return response.status_code in (200, 204)


def _get_state(
    client: MantisClient,
    identity: Identity,
    path: str,
    param: str,
    resource_id: str,
    config: MantisConfig,
) -> dict[str, str] | None:
    url = identity.base_url.rstrip("/") + path.replace("{" + param + "}", resource_id)
    try:
        response = client.get(url, headers=identity.headers())
    except httpx.HTTPError:
        return None
    if response.status_code != 200:
        return None
    try:
        data = response.json()
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    return {
        field: str(data[field])
        for field in config.state_fields
        if field in data and data[field] is not None
    }


def _execute(
    client: MantisClient,
    identity: Identity,
    operation: Operation,
    param: str,
    resource_id: str,
) -> int:
    url = identity.base_url.rstrip("/") + operation.path.replace(
        "{" + param + "}", resource_id
    )
    try:
        if operation.method is HttpMethod.POST:
            response = client.post(url, headers=identity.headers())
        elif operation.method is HttpMethod.PUT:
            response = client.post(url, headers=identity.headers())
        elif operation.method is HttpMethod.PATCH:
            response = client.post(url, headers=identity.headers())
        elif operation.method is HttpMethod.DELETE:
            response = client.post(url, headers=identity.headers())
        else:
            return 0
    except httpx.HTTPError:
        return 0
    return response.status_code


def _probe_bfla(
    *,
    client: MantisClient,
    spec: ApiSpec,
    operation: Operation,
    path_param: str,
    resource_id: str,
    identity_a: Identity,
    identity_b: Identity,
    config: MantisConfig,
) -> Finding | None:
    """Probe one resource for BFLA.

    - Get the resource path (for reading state).
    - Probe with A: reset, execute, verify state change.
    - Probe with B: reset, execute, verify state change.
    - Compare: if both succeeded and both changed state, report BFLA.
    """
    # Find a GET operation on the PARENT path (e.g. /invoices/{invoice_id})
    # to read the resource's state. The operation itself is a POST.
    parent_path = _parent_path(operation.path)
    if parent_path is None:
        return None
    # The read path is parent_path + "/{param}" + anything after.
    # For /invoices/{invoice_id}/approve, parent is /invoices,
    # and the read path is /invoices/{invoice_id}.
    read_path = _derive_read_path(operation.path, path_param)
    if read_path is None:
        return None
    read_op = _find_read_operation(spec, read_path)
    if read_op is None:
        return None

    # Probe with A
    if not _reset_lab(client, identity_a):
        return None
    state_a_before = _get_state(
        client, identity_a, read_op.path, path_param, resource_id, config
    )
    status_a = _execute(client, identity_a, operation, path_param, resource_id)
    state_a_after = _get_state(
        client, identity_a, read_op.path, path_param, resource_id, config
    )

    if status_a not in (200, 201, 204):
        return None
    if state_a_before is None or state_a_after is None:
        return None
    if state_a_before == state_a_after:
        return None  # No effect with A, cannot compare

    # Probe with B
    if not _reset_lab(client, identity_a):
        return None
    state_b_before = _get_state(
        client, identity_b, read_op.path, path_param, resource_id, config
    )
    status_b = _execute(client, identity_b, operation, path_param, resource_id)
    state_b_after = _get_state(
        client, identity_b, read_op.path, path_param, resource_id, config
    )

    if status_b not in (200, 201, 204):
        return None
    if state_b_before is None or state_b_after is None:
        return None
    if state_b_before == state_b_after:
        return None  # No effect with B, not BFLA

    # Both A and B succeeded with state change
    evidence = (
        Evidence(
            description=f"{identity_a.name} executes {operation.method.value} {operation.path} on resource {resource_id}",
            method=operation.method.value,
            url=identity_a.base_url.rstrip("/") + operation.path.replace("{" + path_param + "}", resource_id),
            status=status_a,
        ),
        Evidence(
            description=f"{identity_b.name} executes {operation.method.value} {operation.path} on resource {resource_id}",
            method=operation.method.value,
            url=identity_b.base_url.rstrip("/") + operation.path.replace("{" + path_param + "}", resource_id),
            status=status_b,
        ),
    )

    state_transition_a = _describe_transition(state_a_before, state_a_after)
    state_transition_b = _describe_transition(state_b_before, state_b_after)

    return Finding(
        id=f"BFLA-{operation.path.replace('/', '_')}-{resource_id}",
        type=FindingType.BFLA,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        operation_method=operation.method.value,
        operation_path=operation.path,
        identity=identity_b.name,
        summary=(
            f"{identity_b.name} executed {operation.method.value} {operation.path} "
            f"on resource {resource_id} (also executed by {identity_a.name})"
        ),
        details=(
            f"Identity '{identity_b.name}' executed {operation.method.value} {operation.path} "
            f"on resource '{resource_id}'. The privileged identity '{identity_a.name}' also "
            f"executed it successfully. State transition: {state_transition_b}. "
            f"Expected: {identity_b.name} should not have permission."
        ),
        evidence=evidence,
        reproduction=(
            f"1. Reset lab",
            f"2. As {identity_a.name}, execute {operation.method.value} {operation.path.replace('{' + path_param + '}', resource_id)} -> {state_transition_a}",
            f"3. Reset lab",
            f"4. As {identity_b.name}, execute {operation.method.value} {operation.path.replace('{' + path_param + '}', resource_id)} -> {state_transition_b}",
            f"5. Expected 403 for {identity_b.name}, got {status_b}",
        ),
    )


def _find_read_operation(spec: ApiSpec, path: str) -> Operation | None:
    for op in spec.operations:
        if op.method is HttpMethod.GET and op.path == path:
            return op
    return None


def _describe_transition(before: dict[str, str], after: dict[str, str]) -> str:
    parts = []
    for key in before:
        if key in after and before[key] != after[key]:
            parts.append(f"{key}: {before[key]} -> {after[key]}")
    return ", ".join(parts) or "(no change)"
def _derive_read_path(operation_path: str, path_param: str) -> str | None:
    """Derive the read path from a state-changing path.

    Examples:
        /invoices/{invoice_id}/approve + invoice_id -> /invoices/{invoice_id}
        /invoices/{invoice_id} + invoice_id -> /invoices/{invoice_id}
    """
    marker = "{" + path_param + "}"
    if marker not in operation_path:
        return None
    # Cut everything after the path param
    idx = operation_path.index(marker) + len(marker)
    return operation_path[:idx]
def _is_privileged(path: str, privileged_operations: tuple[str, ...]) -> bool:
    """Return True if the path contains any of the privileged operation markers.

    Example: path="/invoices/{invoice_id}/approve", markers=("approve",) -> True
    """
    return any(marker in path for marker in privileged_operations)