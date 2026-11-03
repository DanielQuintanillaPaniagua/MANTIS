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
    """Execute a state-changing operation using its declared HTTP method.

    Limitation: no request body is sent. This is fine for the lab (POST
    with no body). For APIs that require a body on PUT/PATCH/POST, this
    will fail or produce misleading results. Documented in MK-006.md.
    """
    url = identity.base_url.rstrip("/") + operation.path.replace(
        "{" + param + "}", resource_id
    )
    try:
        response = client.request(
            operation.method.value, url, headers=identity.headers()
        )
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
def detect_state_skip(
    spec: ApiSpec,
    client: MantisClient,
    config: MantisConfig,
    identity_a: Identity,
) -> tuple[Finding, ...]:
    """Detect state skip vulnerabilities.

    Strategy:
    1. Reset lab, list resources in 'draft' state.
    2. Observe natural transition: the first state-changing operation
       that succeeds on a 'draft' resource and changes its state.
    3. For each other state-changing operation:
       - Reset lab, get a 'draft' resource.
       - Execute the operation.
       - If state changed, report STATE_SKIP.

    Requires /lab/reset in the spec. Returns () otherwise.
    """
    reset_available = any(
        op.method is HttpMethod.POST and op.path == RESET_PATH
        for op in spec.operations
    )
    if not reset_available:
        return ()

    # Find candidate state-changing operations with a path param
    state_ops = []
    for op in spec.operations:
        if op.method not in STATE_CHANGING_METHODS:
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
        read_op = _find_read_operation(spec, read_path)
        if read_op is None:
            continue
        state_ops.append((op, path_param, read_op))

    if len(state_ops) < 2:
        return ()  # Need at least two to distinguish natural from skip

    # Parse allowed_transitions if configured
    allowed = _parse_transitions(config.allowed_transitions)

    # Determine the natural transition.
    # If allowed_transitions is configured, use it to identify which
    # operations are "allowed" (natural). Otherwise, fall back to the
    # heuristic: first op in spec order that moves a draft resource.
    natural_op_paths: set[str] = set()
    use_declared = bool(allowed)

    if use_declared:
        # Find which operations produce an allowed transition
        for op, path_param, read_op in state_ops:
            if not _reset_lab(client, identity_a):
                continue
            draft_id = _find_draft_resource(
                client, identity_a, read_op.path, path_param, config
            )
            if draft_id is None:
                continue
            status_before = _get_state(
                client, identity_a, read_op.path, path_param, draft_id, config
            )
            if status_before is None:
                continue
            status_code = _execute(client, identity_a, op, path_param, draft_id)
            if status_code not in (200, 201, 204):
                continue
            status_after = _get_state(
                client, identity_a, read_op.path, path_param, draft_id, config
            )
            if status_after is None or status_after == status_before:
                continue
            if _is_allowed_transition(allowed, status_before, status_after):
                natural_op_paths.add(op.path)

        if not natural_op_paths:
            return ()  # No allowed transition found. Nothing to compare.
    else:
        # Fallback: heuristic by spec order
        for op, path_param, read_op in state_ops:
            if not _reset_lab(client, identity_a):
                continue
            draft_id = _find_draft_resource(
                client, identity_a, read_op.path, path_param, config
            )
            if draft_id is None:
                continue
            status_before = _get_state(
                client, identity_a, read_op.path, path_param, draft_id, config
            )
            if status_before is None:
                continue
            status_code = _execute(client, identity_a, op, path_param, draft_id)
            if status_code not in (200, 201, 204):
                continue
            status_after = _get_state(
                client, identity_a, read_op.path, path_param, draft_id, config
            )
            if status_after is None or status_after == status_before:
                continue
            natural_op_paths.add(op.path)
            break

    if not natural_op_paths:
        return ()  # Cannot determine natural flow

    # Phase 2: probe operations that are not part of the natural flow
    findings: list[Finding] = []
    for op, path_param, read_op in state_ops:
        if op.path in natural_op_paths:
            continue

        if not _reset_lab(client, identity_a):
            continue
        draft_id = _find_draft_resource(
            client, identity_a, read_op.path, path_param, config
        )
        if draft_id is None:
            continue
        status_before = _get_state(
            client, identity_a, read_op.path, path_param, draft_id, config
        )
        if status_before is None:
            continue
        status_code = _execute(client, identity_a, op, path_param, draft_id)
        status_after = _get_state(
            client, identity_a, read_op.path, path_param, draft_id, config
        )

        if status_code not in (200, 201, 204):
            continue
        if status_after is None or status_after == status_before:
            continue

        transition = _describe_transition(status_before, status_after)
        url = identity_a.base_url.rstrip("/") + op.path.replace(
            "{" + path_param + "}", draft_id
        )

        findings.append(
            Finding(
                id=f"STATE_SKIP-{op.path.replace('/', '_')}-{draft_id}",
                type=FindingType.STATE_SKIP,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                operation_method=op.method.value,
                operation_path=op.path,
                identity=identity_a.name,
                summary=(
                    f"{op.method.value} {op.path} moved a resource from "
                    f"{_primary_state(status_before)} to "
                    f"{_primary_state(status_after)}, skipping the natural flow"
                ),
                details=(
                    f"Operation {op.method.value} {op.path} executed on a resource "
                    f"in its initial state ({status_before}) and changed it to "
                    f"{status_after}. The natural flow (observed on "
                    f"{', '.join(sorted(natural_op_paths))}) was skipped."
                ),
                evidence=(
                    Evidence(
                        description=f"{identity_a.name} executes {op.method.value} {op.path} on resource {draft_id}",
                        method=op.method.value,
                        url=url,
                        status=status_code,
                    ),
                ),
                reproduction=(
                    "1. Reset lab",
                    f"2. Find a resource in state {_primary_state(status_before)}",
                    f"3. Execute {op.method.value} {url}",
                    f"4. Observe state transition: {transition}",
                    f"5. Expected 409 (transition not allowed in this state), got {status_code}",
                ),
            )
        )

    return tuple(findings)


def _find_draft_resource(
    client: MantisClient,
    identity: Identity,
    read_path: str,
    path_param: str,
    config: MantisConfig,
) -> str | None:
    """Find a resource in the first state_field value 'draft' (or first state found)."""
    parent_path = read_path.split("/{", 1)[0]
    ids = _list_resource_ids(client, identity, parent_path)
    for resource_id in ids:
        state = _get_state(client, identity, read_path, path_param, resource_id, config)
        if state is None:
            continue
        # Consider "draft" or any state whose primary value is "draft"
        primary = _primary_state(state)
        if primary == "draft":
            return resource_id
    return None


def _primary_state(state: dict[str, str]) -> str:
    """Return the first state value, for human-readable messages."""
    for value in state.values():
        return value
    return "(unknown)"
def _parse_transitions(
    raw: tuple[str, ...],
) -> dict[str, dict[str, list[str]]]:
    """Parse allowed_transitions strings like 'status:draft->submitted'.

    Returns {field: {from_state: [to_state, ...]}}.
    Malformed entries are silently skipped.
    """
    result: dict[str, dict[str, list[str]]] = {}
    for item in raw:
        if ":" not in item or "->" not in item:
            continue
        field, transition = item.split(":", 1)
        src, dst = transition.split("->", 1)
        field = field.strip()
        src = src.strip()
        dst = dst.strip()
        if not field or not src or not dst:
            continue
        result.setdefault(field, {}).setdefault(src, []).append(dst)
    return result


def _is_allowed_transition(
    allowed: dict[str, dict[str, list[str]]],
    before: dict[str, str],
    after: dict[str, str],
) -> bool:
    """Check if the transition from `before` to `after` is in `allowed`.

    A transition is allowed if, for each field that changed, the change
    is declared. Fields that did not change are ignored.
    """
    any_change = False
    for field, before_value in before.items():
        if field not in after:
            continue
        after_value = after[field]
        if before_value == after_value:
            continue
        any_change = True
        # Check declared transitions for this field
        field_transitions = allowed.get(field, {})
        allowed_targets = field_transitions.get(before_value, [])
        if after_value not in allowed_targets:
            return False
    return any_change