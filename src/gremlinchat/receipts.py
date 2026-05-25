"""Signed Trust Receipts for local GremlinChat evidence."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from pathlib import Path
from typing import Any

from .crypto import NodeIdentity
from .jsonutil import canonical_bytes
from .redaction import redact_value
from .store import ensure_home, load_or_create_identity

RECEIPT_SCHEMA = "gremlinchat.receipt.v1"
BUNDLE_SCHEMA = "gremlinchat.receipt-bundle.v1"


def create_receipt(
    home: Path,
    *,
    event_type: str,
    status: str,
    evidence: dict[str, Any] | None = None,
    room_id: str | None = None,
    task_id: str | None = None,
    runbook: str | None = None,
    dedupe_key: str | None = None,
) -> dict[str, Any]:
    home = ensure_home(home)
    identity = load_or_create_identity(home)
    safe_evidence = sanitize_receipt_value(home, {} if evidence is None else evidence)
    evidence_hash = _sha256_hex(canonical_bytes(safe_evidence))
    dedupe = _dedupe_payload(
        identity.node_id,
        event_type=event_type,
        status=status,
        evidence_hash=evidence_hash,
        room_id=room_id,
        task_id=task_id,
        runbook=runbook,
        dedupe_key=dedupe_key,
        include_evidence_hash=dedupe_key is None,
    )
    receipt_id = "receipt_" + _sha256_hex(canonical_bytes(dedupe))[:24]
    paths = _receipt_paths(home, receipt_id)
    if paths["json"].exists():
        return load_receipt(paths["json"])

    unsigned = {
        "schema": RECEIPT_SCHEMA,
        "receipt_id": receipt_id,
        "created_at": round(time.time(), 3),
        "issuer_node_id": identity.node_id,
        "issuer_public_key": identity.public_key,
        "event_type": event_type,
        "status": status,
        "room_id": room_id,
        "task_id": task_id,
        "runbook": runbook,
        "evidence": safe_evidence,
        "evidence_hash": evidence_hash,
        "dedupe_key_hash": _sha256_hex(canonical_bytes(dedupe)),
        "trust_statement": "This proves only that the issuer node signed this redacted evidence; it does not prove the issuer is trusted.",
    }
    receipt = {**unsigned, "signature": identity.sign(canonical_bytes(unsigned))}
    paths["dir"].mkdir(parents=True, exist_ok=True)
    paths["json"].write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")
    paths["markdown"].write_text(receipt_markdown(receipt), encoding="utf-8")
    return receipt


def load_receipt(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def find_receipt(home: Path, receipt_id_or_path: str) -> dict[str, Any]:
    candidate = Path(receipt_id_or_path)
    if candidate.exists():
        return load_receipt(candidate)
    receipt_id = receipt_id_or_path[:-5] if receipt_id_or_path.endswith(".json") else receipt_id_or_path
    path = ensure_home(home) / "receipts" / f"{receipt_id}.json"
    if not path.exists():
        raise FileNotFoundError(f"Unknown GremlinChat receipt: {receipt_id_or_path}")
    return load_receipt(path)


def list_receipts(home: Path, *, limit: int = 25, room_id: str | None = None) -> list[dict[str, Any]]:
    receipts_dir = ensure_home(home) / "receipts"
    if not receipts_dir.exists():
        return []
    rows = []
    for path in receipts_dir.glob("receipt_*.json"):
        try:
            receipt = load_receipt(path)
        except (OSError, json.JSONDecodeError):
            continue
        if room_id and receipt.get("room_id") != room_id:
            continue
        rows.append(receipt)
    rows.sort(key=lambda item: float(item.get("created_at", 0)), reverse=True)
    return rows[:limit]


def receipt_status(home: Path, *, limit: int = 10) -> dict[str, Any]:
    rows = list_receipts(home, limit=limit)
    return {
        "schema": "gremlinchat.receipt-status.v1",
        "count": _receipt_count(home),
        "latest": [receipt_summary(item) for item in rows],
    }


def receipt_summary(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        "receipt_id": receipt.get("receipt_id"),
        "created_at": receipt.get("created_at"),
        "issuer_node_id": receipt.get("issuer_node_id"),
        "event_type": receipt.get("event_type"),
        "status": receipt.get("status"),
        "room_id": receipt.get("room_id"),
        "task_id": receipt.get("task_id"),
        "runbook": receipt.get("runbook"),
        "evidence_hash": receipt.get("evidence_hash"),
        "verification_hint": "Run gremlinchat receipt verify <path> to verify signature and evidence hash.",
    }


def verify_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    if receipt.get("schema") != RECEIPT_SCHEMA:
        errors.append("unsupported receipt schema")
    evidence = receipt.get("evidence")
    expected_hash = _sha256_hex(canonical_bytes(evidence))
    if receipt.get("evidence_hash") != expected_hash:
        errors.append("evidence hash mismatch")
    signature = str(receipt.get("signature", ""))
    unsigned = dict(receipt)
    unsigned.pop("signature", None)
    issuer = NodeIdentity(str(receipt.get("issuer_node_id", "")), str(receipt.get("issuer_public_key", "")))
    try:
        signature_ok = bool(signature) and issuer.verify(canonical_bytes(unsigned), signature)
    except Exception:
        signature_ok = False
    if not signature_ok:
        errors.append("signature verification failed")
    return {
        "schema": "gremlinchat.receipt-verification.v1",
        "ok": not errors,
        "receipt_id": receipt.get("receipt_id"),
        "issuer_node_id": receipt.get("issuer_node_id"),
        "event_type": receipt.get("event_type"),
        "errors": errors,
        "statement": "Valid means the receipt was signed by the issuer key and has not been altered; it does not establish trust in the issuer.",
    }


def verify_receipt_file(path: str | Path) -> dict[str, Any]:
    return verify_receipt(load_receipt(path))


def write_receipt_bundle(home: Path, *, room_id: str | None = None) -> dict[str, str]:
    home = ensure_home(home)
    receipts = list_receipts(home, limit=10000, room_id=room_id)
    bundle = {
        "schema": BUNDLE_SCHEMA,
        "created_at": round(time.time(), 3),
        "room_id": room_id,
        "count": len(receipts),
        "receipts": receipts,
        "verification": [verify_receipt(item) for item in receipts],
    }
    safe_bundle = sanitize_receipt_value(home, bundle)
    reports_dir = home / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    suffix = uuid.uuid4().hex[:8]
    json_path = reports_dir / f"receipt-bundle-{stamp}-{suffix}.json"
    md_path = reports_dir / f"receipt-bundle-{stamp}-{suffix}.md"
    json_path.write_text(json.dumps(safe_bundle, indent=2, sort_keys=True), encoding="utf-8")
    md_path.write_text(bundle_markdown(safe_bundle), encoding="utf-8")
    return {"json": str(json_path), "markdown": str(md_path)}


def sanitize_receipt_value(home: Path, value: Any) -> Any:
    home_text = str(home)
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, nested in value.items():
            key_lower = str(key).lower()
            if any(part in key_lower for part in ["token", "secret", "private", "password", "apikey", "api_key", "authorization", "invite"]):
                result[key] = "[redacted]"
            elif key_lower in {"safety_phrase", "phrase"}:
                result[key] = "[redacted]"
            elif key_lower in {"stdout", "stderr", "command", "raw_log", "raw_logs", "log"}:
                result[key] = "[redacted-log]"
            elif key_lower.endswith("path") or key_lower in {"home", "cwd", "executable"}:
                result[key] = _redact_path(home_text, nested)
            else:
                result[key] = sanitize_receipt_value(home, nested)
        return redact_value(result)
    if isinstance(value, list):
        return [sanitize_receipt_value(home, item) for item in value]
    if isinstance(value, str):
        return redact_value(_redact_path(home_text, value))
    return value


def receipt_markdown(receipt: dict[str, Any]) -> str:
    verification = verify_receipt(receipt)
    return "\n".join(
        [
            "# GremlinChat Trust Receipt",
            "",
            f"- Receipt: `{receipt.get('receipt_id')}`",
            f"- Event: `{receipt.get('event_type')}`",
            f"- Status: `{receipt.get('status')}`",
            f"- Issuer: `{receipt.get('issuer_node_id')}`",
            f"- Room: `{receipt.get('room_id')}`",
            f"- Task: `{receipt.get('task_id')}`",
            f"- Runbook: `{receipt.get('runbook')}`",
            f"- Evidence hash: `{receipt.get('evidence_hash')}`",
            f"- Locally verified: `{verification.get('ok')}`",
            "",
            "This receipt proves only that the issuer node signed the redacted evidence and that the file has not been altered.",
            "",
            "## Evidence",
            "",
            "```json",
            json.dumps(receipt.get("evidence", {}), indent=2, sort_keys=True),
            "```",
            "",
            "## JSON",
            "",
            "```json",
            json.dumps(receipt, indent=2, sort_keys=True),
            "```",
            "",
        ]
    )


def bundle_markdown(bundle: dict[str, Any]) -> str:
    receipt_lines = [
        f"- `{item.get('receipt_id')}` {item.get('event_type')} status=`{item.get('status')}` issuer=`{item.get('issuer_node_id')}`"
        for item in bundle.get("receipts", [])
    ]
    return "\n".join(
        [
            "# GremlinChat Trust Receipt Bundle",
            "",
            f"- Created: `{bundle.get('created_at')}`",
            f"- Room: `{bundle.get('room_id')}`",
            f"- Count: `{bundle.get('count')}`",
            "",
            "## Receipts",
            "",
            *(receipt_lines or ["- No receipts found."]),
            "",
            "## JSON",
            "",
            "```json",
            json.dumps(bundle, indent=2, sort_keys=True),
            "```",
            "",
        ]
    )


def _receipt_paths(home: Path, receipt_id: str) -> dict[str, Path]:
    receipts_dir = home / "receipts"
    return {"dir": receipts_dir, "json": receipts_dir / f"{receipt_id}.json", "markdown": receipts_dir / f"{receipt_id}.md"}


def _dedupe_payload(
    issuer_node_id: str,
    *,
    event_type: str,
    status: str,
    evidence_hash: str,
    room_id: str | None,
    task_id: str | None,
    runbook: str | None,
    dedupe_key: str | None,
    include_evidence_hash: bool,
) -> dict[str, Any]:
    return {
        "issuer_node_id": issuer_node_id,
        "event_type": event_type,
        "status": status,
        "room_id": room_id,
        "task_id": task_id,
        "runbook": runbook,
        "dedupe_key": dedupe_key,
        "evidence_hash": evidence_hash if include_evidence_hash else None,
    }


def _receipt_count(home: Path) -> int:
    receipts_dir = ensure_home(home) / "receipts"
    if not receipts_dir.exists():
        return 0
    return len([path for path in receipts_dir.glob("receipt_*.json") if path.is_file()])


def _sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _redact_path(home_text: str, value: Any) -> Any:
    if not isinstance(value, str):
        return value
    normalized = value.replace("\\", "/")
    home_normalized = home_text.replace("\\", "/")
    if home_normalized and home_normalized in normalized:
        return normalized.replace(home_normalized, "%GREMLINCHAT_HOME%")
    if ":/" in normalized or normalized.startswith("/") or normalized.startswith("~"):
        return "[redacted-path]"
    return value
