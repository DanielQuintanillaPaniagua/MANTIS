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
from mantis.analysis.result import AssessmentState, ScanResult

from mantis.analysis.authorization import Identity, _assess_severity
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

MAX_PROBES_PER_OPERATION = 3


def detect_bfla(
    spec: ApiSpec,
    client: MantisClient,
    config: MantisConfig,
    privileged_identity: Identity,
    test_identities: list[Identity],
) -> ScanResult:
    """Detect BFLA between a privileged and a limited identity.

    Requires /lab/reset in the spec to reset between probes.
    Without reset, returns () and warns.
    """
    if not config.reset_endpoint:
        return ScanResult(state=AssessmentState.OMITTED, reason="No reset_endpoint configured.")

    findings: list[Finding] = []

    if not config.privileged_operations:
        return ScanResult(state=AssessmentState.OMITTED, reason="No privileged_operations configured.")

    for op in spec.operations:
        if op.method not in STATE_CHANGING_METHODS:
            continue
        if not _is_privileged(op.path, config.privileged_operations):
            continue
        path_param = _first_path_param(op)
        if path_param is None:
            continue

        parent_path = _parent_path(op.path)
        if parent_path is None:
            continue

        for test_identity in test_identities:
            b_resources = _list_resource_ids(client, test_identity, parent_path, config)
            if not b_resources:
                continue

            for resource_id in b_resources[:MAX_PROBES_PER_OPERATION]:
                finding = _probe_bfla(
                    client=client,
                    spec=spec,
                    operation=op,
                    path_param=path_param,
                    resource_id=resource_id,
                    identity_a=privileged_identity,
                    identity_b=test_identity,
                    config=config,
                )
                if finding is not None:
                    findings.append(finding)

    if findings:
        return ScanResult(state=AssessmentState.CONFIRMED, findings=tuple(findings))
    return ScanResult(state=AssessmentState.NOT_FOUND)


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
    client: MantisClient, identity: Identity, parent_path: str, config: MantisConfig
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
    """Probe one resource for BFLA."""
    parent_path = _parent_path(operation.path)
    if parent_path is None:
        return None
    read_path = _derive_read_path(operation.path, path_param)
    if read_path is None:
        return None
    read_op = _find_read_operation(spec, read_path)
    if read_op is None:
        return None

    # Probe with A
    if not _reset_lab(client, identity_a, config):
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
        return None

    # Probe with B
    if not _reset_lab(client, identity_a, config):
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
        return None

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
        severity=_assess_severity(operation.method),
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
    marker = "{" + path_param + "}"
    if marker not in operation_path:
        return None
    idx = operation_path.index(marker) + len(marker)
    return operation_path[:idx]


def _is_privileged(path: str, privileged_operations: tuple[str, ...]) -> bool:
    return any(marker in path for marker in privileged_operations)


def detect_state_skip(
    spec: ApiSpec,
    client: MantisClient,
    config: MantisConfig,
    test_identities: list[Identity],
    reset_identity: Identity | None = None,
) -> ScanResult:
    """Detect state skip vulnerabilities.

    `reset_identity` is the identity used to call the reset endpoint. It
    usually needs privileges (e.g. admin), so it must not default to the
    limited test identity. If omitted, the first test identity is used.
    """
    if not config.reset_endpoint:
        return ScanResult(state=AssessmentState.OMITTED, reason="No reset_endpoint configured.")
    if not test_identities:
        return ScanResult(state=AssessmentState.OMITTED, reason="No test identities provided.")

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
        return ScanResult(state=AssessmentState.OMITTED, reason="Not enough state-changing operations found.")

    allowed = _parse_transitions(config.allowed_transitions)
    natural_op_paths: set[str] = set()
    use_declared = bool(allowed)

    # Usamos la primera identidad disponible como referencia
    primary_identity = test_identities[0]
    resetter = reset_identity or primary_identity

    if use_declared:
        for op, path_param, read_op in state_ops:
            if not _reset_lab(client, resetter, config):
                continue
            draft_id = _find_draft_resource(
                client, primary_identity, read_op.path, path_param, config
            )
            if draft_id is None:
                continue
            status_before = _get_state(
                client, primary_identity, read_op.path, path_param, draft_id, config
            )
            if status_before is None:
                continue
            status_code = _execute(client, primary_identity, op, path_param, draft_id)
            if status_code not in (200, 201, 204):
                continue
            status_after = _get_state(
                client, primary_identity, read_op.path, path_param, draft_id, config
            )
            if status_after is None or status_after == status_before:
                continue
            if _is_allowed_transition(allowed, status_before, status_after):
                natural_op_paths.add(op.path)

        if not natural_op_paths:
            return ScanResult(state=AssessmentState.INCONCLUSIVE, reason="Could not determine natural transition.")
    else:
        for op, path_param, read_op in state_ops:
            if not _reset_lab(client, resetter, config):
                continue
            draft_id = _find_draft_resource(
                client, primary_identity, read_op.path, path_param, config
            )
            if draft_id is None:
                continue
            status_before = _get_state(
                client, primary_identity, read_op.path, path_param, draft_id, config
            )
            if status_before is None:
                continue
            status_code = _execute(client, primary_identity, op, path_param, draft_id)
            if status_code not in (200, 201, 204):
                continue
            status_after = _get_state(
                client, primary_identity, read_op.path, path_param, draft_id, config
            )
            if status_after is None or status_after == status_before:
                continue
            natural_op_paths.add(op.path)
            break

    if not natural_op_paths:
        return ScanResult(state=AssessmentState.INCONCLUSIVE, reason="Could not determine natural transition.")

    findings: list[Finding] = []
    for op, path_param, read_op in state_ops:
        if op.path in natural_op_paths:
            continue

        if not _reset_lab(client, resetter, config):
            continue
        draft_id = _find_draft_resource(
            client, primary_identity, read_op.path, path_param, config
        )
        if draft_id is None:
            continue
        status_before = _get_state(
            client, primary_identity, read_op.path, path_param, draft_id, config
        )
        if status_before is None:
            continue
        status_code = _execute(client, primary_identity, op, path_param, draft_id)
        status_after = _get_state(
            client, primary_identity, read_op.path, path_param, draft_id, config
        )

        if status_code not in (200, 201, 204):
            continue
        if status_after is None or status_after == status_before:
            continue

        transition = _describe_transition(status_before, status_after)
        url = primary_identity.base_url.rstrip("/") + op.path.replace(
            "{" + path_param + "}", draft_id
        )

        findings.append(
            Finding(
                id=f"STATE_SKIP-{op.path.replace('/', '_')}-{draft_id}",
                type=FindingType.STATE_SKIP,
                severity=_assess_severity(op.method),
                confidence=Confidence.MEDIUM,
                operation_method=op.method.value,
                operation_path=op.path,
                identity=primary_identity.name,
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
                        description=f"{primary_identity.name} executes {op.method.value} {op.path} on resource {draft_id}",
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

    if findings:
        return ScanResult(state=AssessmentState.CONFIRMED, findings=tuple(findings))
    return ScanResult(state=AssessmentState.NOT_FOUND)


def _find_draft_resource(
    client: MantisClient,
    identity: Identity,
    read_path: str,
    path_param: str,
    config: MantisConfig,
) -> str | None:
    """Find a resource in the first state_field value 'draft' (or first state found)."""
    parent_path = read_path.split("/{", 1)[0]
    ids = _list_resource_ids(client, identity, parent_path, config)
    for resource_id in ids:
        state = _get_state(client, identity, read_path, path_param, resource_id, config)
        if state is None:
            continue
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
    """Parse allowed_transitions strings like 'status:draft->submitted'."""
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
    """Check if the transition from `before` to `after` is in `allowed`."""
    any_change = False
    for field, before_value in before.items():
        if field not in after:
            continue
        after_value = after[field]
        if before_value == after_value:
            continue
        any_change = True
        field_transitions = allowed.get(field, {})
        allowed_targets = field_transitions.get(before_value, [])
        if after_value not in allowed_targets:
            return False
    return any_change