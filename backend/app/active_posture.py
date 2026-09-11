from __future__ import annotations

from typing import Any

from app.models import JobRecord


ACTIVE_POSTURE_CONTRACT_VERSION = "2026-09-09.1"
_TERMINAL = {"completed", "failed", "cancelled"}
_HTTP_BOOLEAN_INDICATORS = {
    "hsts_present",
    "csp_present",
    "x_content_type_options_present",
    "x_frame_options_present",
    "referrer_policy_present",
    "permissions_policy_present",
    "server_header_present",
    "server_header_value_redacted",
    "set_cookie_present",
    "set_cookie_count_truncated",
    "set_cookie_secure_attribute_present",
    "set_cookie_httponly_attribute_present",
    "set_cookie_samesite_attribute_present",
    "location_header_present",
}
_TLS_PROTOCOLS = {"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}


def build_active_posture(
    jobs: list[JobRecord],
    *,
    baseline_execution_id: str | None = None,
    capability: str | None = None,
) -> dict[str, Any]:
    ordered = sorted(
        (job for job in jobs if job.status in _TERMINAL and (capability is None or job.audit_type == capability)),
        key=lambda job: (job.created_at, job.id),
    )
    by_capability: dict[str, list[JobRecord]] = {}
    for job in ordered:
        by_capability.setdefault(job.audit_type, []).append(job)

    selected: list[JobRecord] = []
    if baseline_execution_id:
        baseline = next((job for job in ordered if job.id == baseline_execution_id), None)
        if baseline is not None:
            compatible = by_capability.get(baseline.audit_type, [])
            latest = compatible[-1] if compatible else None
            if latest is not None and latest.id != baseline.id:
                selected = [baseline, latest]
    elif capability and len(by_capability.get(capability, [])) >= 2:
        selected = by_capability[capability][-2:]
    else:
        candidates = [items[-2:] for items in by_capability.values() if len(items) >= 2]
        if candidates:
            selected = max(candidates, key=lambda pair: pair[-1].created_at)

    comparison = _comparison(selected[0], selected[1]) if len(selected) == 2 else None
    return {
        "contract_version": ACTIVE_POSTURE_CONTRACT_VERSION,
        "execution_count": len(ordered),
        "counts": {
            "completed": sum(job.status == "completed" for job in ordered),
            "failed": sum(job.status == "failed" for job in ordered),
            "cancelled": sum(job.status == "cancelled" for job in ordered),
        },
        "capabilities": [
            {
                "capability": name,
                "execution_count": len(items),
                "latest_execution_id": items[-1].id,
                "latest_status": items[-1].status,
                "latest_at": items[-1].updated_at,
                "latest_authorization_revision_id": items[-1].active_authorization_revision_id,
                "latest_authorization_revision_sequence": items[-1].active_authorization_revision_sequence,
            }
            for name, items in sorted(by_capability.items())
        ],
        "baseline_execution_id": baseline_execution_id,
        "comparison": comparison,
        "limitations": [
            "Comparisons use only redacted, normalized observations from the same capability.",
            "A disappeared port is not presented as a resolved vulnerability.",
            "A missing header or observed DNS name is an indicator requiring manual validation, not proof of exploitation.",
            "Coverage, truncation and controlled errors can make changes inconclusive.",
        ],
    }


def _comparison(base: JobRecord, target: JobRecord) -> dict[str, Any]:
    base_snapshot = build_active_evidence_snapshot(base)
    target_snapshot = build_active_evidence_snapshot(target)
    keys = sorted(set(base_snapshot["signals"]) | set(target_snapshot["signals"]))
    changes: list[dict[str, Any]] = []
    persistent = 0
    for key in keys:
        before = base_snapshot["signals"].get(key)
        after = target_snapshot["signals"].get(key)
        if before == after:
            persistent += 1
            continue
        kind = "new" if before is None else "disappeared" if after is None else "changed"
        changes.append(
            {
                "kind": kind,
                "signal": key,
                "before": before,
                "after": after,
                "interpretation": _interpretation(base.audit_type, key, before, after),
            }
        )
    revision_unknown = (
        base.active_authorization_revision_id is None
        or target.active_authorization_revision_id is None
    )
    incomplete = bool(
        base_snapshot["coverage"]["incomplete"]
        or target_snapshot["coverage"]["incomplete"]
        or revision_unknown
    )
    return {
        "state": "inconclusive" if incomplete else "ready",
        "capability": base.audit_type,
        "base_execution_id": base.id,
        "target_execution_id": target.id,
        "summary": {
            "new": sum(item["kind"] == "new" for item in changes),
            "changed": sum(item["kind"] == "changed" for item in changes),
            "disappeared": sum(item["kind"] == "disappeared" for item in changes),
            "persistent": persistent,
        },
        "changes": changes[:200],
        "changes_truncated": len(changes) > 200,
        "coverage": {"base": base_snapshot["coverage"], "target": target_snapshot["coverage"]},
        "authorization": {
            "base": _authorization_revision_reference(base),
            "target": _authorization_revision_reference(target),
            "same_revision": (
                base.active_authorization_revision_id == target.active_authorization_revision_id
                if not revision_unknown
                else None
            ),
        },
    }


def _authorization_revision_reference(job: JobRecord) -> dict[str, Any]:
    if job.active_authorization_revision_id is None or job.active_authorization_revision_sequence is None:
        return {"id": None, "sequence": None, "label": "unknown (legacy)"}
    return {
        "id": job.active_authorization_revision_id,
        "sequence": job.active_authorization_revision_sequence,
        "label": f"r{job.active_authorization_revision_sequence}:{job.active_authorization_revision_id[:12]}",
    }


def build_active_evidence_snapshot(job: JobRecord) -> dict[str, Any]:
    """Project a stored Active result to the closed, target-free evidence set."""
    result = job.result if isinstance(job.result, dict) else {}
    signals: dict[str, str | int | bool] = {}
    if job.audit_type == "active_nmap_basic":
        observations = result.get("port_observations")
        if isinstance(observations, list):
            for item in observations[:200]:
                if not isinstance(item, dict):
                    continue
                port, protocol, state = item.get("port"), item.get("protocol"), item.get("state")
                if isinstance(port, int) and 1 <= port <= 65535 and protocol == "tcp" and state in {"open", "closed", "filtered"}:
                    signals[f"tcp_port:{port}"] = state
    elif job.audit_type == "active_dns_inventory":
        records = result.get("records")
        if isinstance(records, dict):
            for record_type, group in records.items():
                if record_type in {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA"} and isinstance(group, dict):
                    count = group.get("count")
                    if isinstance(count, int) and count >= 0:
                        signals[f"dns_count:{record_type}"] = count
        security = result.get("security_records")
        if isinstance(security, dict):
            for name in ("spf", "dmarc", "caa"):
                value = security.get(name)
                if isinstance(value, dict) and isinstance(value.get("present"), bool):
                    signals[f"dns_indicator:{name}"] = value["present"]
    elif job.audit_type == "active_dns_osint":
        observed = result.get("observed_names")
        if isinstance(observed, dict) and isinstance(observed.get("count"), int):
            signals["dns_osint:observed_name_count"] = max(0, observed["count"])
    elif job.audit_type == "active_http_basic_header_review":
        indicators = result.get("header_indicators")
        if isinstance(indicators, dict):
            for key, value in indicators.items():
                if key in _HTTP_BOOLEAN_INDICATORS and isinstance(value, bool):
                    signals[f"http_header:{key}"] = value
    elif job.audit_type == "active_tls_basic":
        handshake = result.get("handshake")
        certificate = result.get("certificate")
        if isinstance(handshake, dict) and handshake.get("protocol") in _TLS_PROTOCOLS:
            signals["tls:protocol"] = handshake["protocol"]
        if isinstance(certificate, dict):
            if isinstance(certificate.get("available"), bool):
                signals["tls:certificate_available"] = certificate["available"]
            if isinstance(certificate.get("days_until_expiry"), int):
                signals["tls:certificate_days_remaining"] = certificate["days_until_expiry"]

    limits = result.get("limits") if isinstance(result.get("limits"), dict) else {}
    errors = result.get("errors") if isinstance(result.get("errors"), list) else []
    incomplete = job.status != "completed" or bool(errors) or any(
        bool(limits.get(key)) for key in ("output_truncated", "stderr_truncated", "timed_out", "truncated")
    ) or result.get("coverage_level") in {"partial_inventory"}
    return {
        "signals": signals,
        "coverage": {
            "job_status": job.status,
            "result_status": str(result.get("result_status") or result.get("status") or "unknown")[:64],
            "incomplete": incomplete,
            "truncated": any(bool(limits.get(key)) for key in ("output_truncated", "stderr_truncated", "truncated")),
            "controlled_error_count": min(len(errors), 100),
        },
    }


def _interpretation(capability: str, key: str, before: Any, after: Any) -> str:
    if capability == "active_nmap_basic":
        if before is None:
            return "New TCP port observation; validate service ownership and intended exposure."
        if after is None:
            return "TCP port no longer observed; this is not a resolved-vulnerability claim."
        return "TCP port state changed; validate against network and service context."
    if capability == "active_http_basic_header_review":
        if before is True and after is False:
            return "Possible header regression; validate applicability before prioritizing."
        if before is False and after is True:
            return "Header now observed; this is a configuration improvement, not proof of risk removal."
        return "HTTP header indicator changed; manual validation required."
    if capability.startswith("active_dns_"):
        return "DNS observation changed; observed names and records are not automatically authorized targets."
    if capability == "active_tls_basic":
        return "TLS observation changed; validate protocol and certificate context manually."
    return "Bounded observation changed; manual validation required."
