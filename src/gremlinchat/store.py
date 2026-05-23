"""Local GremlinChat config, policy, approvals, audit, and reports."""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .crypto import NodeIdentity, X25519Identity, protect_secret, unprotect_secret
from .redaction import redact_value


def default_home() -> Path:
    root = os.environ.get("LOCALAPPDATA")
    if root:
        return Path(root) / "GremlinChat"
    return Path.home() / ".gremlinchat"


def ensure_home(home: Path | None = None) -> Path:
    resolved = default_home() if home is None else Path(home)
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


@dataclass
class ApprovedRepo:
    name: str
    path: str
    allow_pull_ff_only: bool = False
    allow_tests: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "allow_pull_ff_only": self.allow_pull_ff_only,
            "allow_tests": list(self.allow_tests),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ApprovedRepo":
        return cls(
            name=str(data["name"]),
            path=str(data["path"]),
            allow_pull_ff_only=bool(data.get("allow_pull_ff_only", False)),
            allow_tests=[str(item) for item in data.get("allow_tests", [])],
        )


@dataclass
class RunbookPolicy:
    emergency_stop: bool = False
    approved_repos: list[ApprovedRepo] = field(default_factory=list)
    enabled_write_runbooks: list[str] = field(default_factory=list)
    allowlisted_tests: dict[str, list[str]] = field(default_factory=dict)
    managed_workers: dict[str, list[str]] = field(default_factory=dict)
    revoked_node_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "emergency_stop": self.emergency_stop,
            "approved_repos": [repo.to_dict() for repo in self.approved_repos],
            "enabled_write_runbooks": list(self.enabled_write_runbooks),
            "allowlisted_tests": dict(self.allowlisted_tests),
            "managed_workers": dict(self.managed_workers),
            "revoked_node_ids": list(self.revoked_node_ids),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RunbookPolicy":
        return cls(
            emergency_stop=bool(data.get("emergency_stop", False)),
            approved_repos=[ApprovedRepo.from_dict(item) for item in data.get("approved_repos", [])],
            enabled_write_runbooks=[str(item) for item in data.get("enabled_write_runbooks", [])],
            allowlisted_tests={str(key): [str(part) for part in value] for key, value in data.get("allowlisted_tests", {}).items()},
            managed_workers={str(key): [str(part) for part in value] for key, value in data.get("managed_workers", {}).items()},
            revoked_node_ids=[str(item) for item in data.get("revoked_node_ids", [])],
        )


def load_or_create_identity(home: Path | None = None) -> NodeIdentity:
    resolved = ensure_home(home)
    path = resolved / "identity.json"
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        return NodeIdentity(data["node_id"], data["public_key"], unprotect_secret(data["private_key_protected"]))
    identity = NodeIdentity.generate()
    path.write_text(
        json.dumps(
            {
                "schema": "gremlinchat.identity.v1",
                "node_id": identity.node_id,
                "public_key": identity.public_key,
                "private_key_protected": protect_secret(identity.private_key or ""),
                "created_at": round(time.time(), 3),
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return identity


def load_or_create_x25519_identity(home: Path | None = None) -> X25519Identity:
    resolved = ensure_home(home)
    path = resolved / "x25519.identity.json"
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        return X25519Identity(unprotect_secret(data["private_key_protected"]), data["public_key"])
    identity = X25519Identity.generate()
    path.write_text(
        json.dumps(
            {
                "schema": "gremlinchat.x25519-identity.v1",
                "public_key": identity.public_key,
                "private_key_protected": protect_secret(identity.private_key),
                "created_at": round(time.time(), 3),
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return identity


def load_policy(home: Path | None = None) -> RunbookPolicy:
    resolved = ensure_home(home)
    path = resolved / "runbook-policy.json"
    if not path.exists():
        policy = RunbookPolicy()
        save_policy(policy, resolved)
        return policy
    return RunbookPolicy.from_dict(json.loads(path.read_text(encoding="utf-8")))


def save_policy(policy: RunbookPolicy, home: Path | None = None) -> None:
    resolved = ensure_home(home)
    (resolved / "runbook-policy.json").write_text(json.dumps(policy.to_dict(), indent=2, sort_keys=True), encoding="utf-8")


def load_rooms(home: Path | None = None) -> list[dict[str, Any]]:
    resolved = ensure_home(home)
    path = resolved / "rooms.json"
    if not path.exists():
        return []
    rooms = []
    for room in json.loads(path.read_text(encoding="utf-8")).get("rooms", []):
        loaded = dict(room)
        for field_name in ["relay_token", "pair_secret"]:
            protected_name = f"{field_name}_protected"
            if protected_name in loaded and field_name not in loaded:
                loaded[field_name] = unprotect_secret(loaded[protected_name])
        rooms.append(loaded)
    return rooms


def save_room(room: dict[str, Any], home: Path | None = None) -> None:
    resolved = ensure_home(home)
    rooms = [existing for existing in load_rooms(resolved) if existing.get("room_id") != room.get("room_id")]
    rooms.append(dict(room))
    (resolved / "rooms.json").write_text(
        json.dumps({"rooms": [_room_for_disk(item) for item in rooms]}, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def _room_for_disk(room: dict[str, Any]) -> dict[str, Any]:
    saved = dict(room)
    for field_name in ["relay_token", "pair_secret"]:
        if field_name in saved:
            saved[f"{field_name}_protected"] = protect_secret(str(saved.pop(field_name)))
    return saved


def append_audit_event(home: Path | None, event: dict[str, Any]) -> dict[str, Any]:
    resolved = ensure_home(home)
    record = {"audit_id": f"audit_{uuid.uuid4().hex}", "created_at": round(time.time(), 3), **redact_value(event)}
    with (resolved / "audit.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    return record


def read_audit_events(home: Path | None, *, limit: int = 50) -> list[dict[str, Any]]:
    path = ensure_home(home) / "audit.jsonl"
    if not path.exists():
        return []
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return rows[-limit:]


def load_approvals(home: Path | None) -> list[dict[str, Any]]:
    path = ensure_home(home) / "approvals.json"
    if not path.exists():
        return []
    return list(json.loads(path.read_text(encoding="utf-8")).get("approvals", []))


def save_approvals(home: Path | None, approvals: list[dict[str, Any]]) -> None:
    (ensure_home(home) / "approvals.json").write_text(
        json.dumps({"approvals": approvals}, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def create_pending_approval(
    home: Path | None,
    *,
    room_id: str,
    task_id: str,
    requester_node_id: str,
    runbook: str,
    payload: dict[str, Any],
    reason: str,
) -> dict[str, Any]:
    approvals = load_approvals(home)
    approval_id = f"approval_{task_id.removeprefix('task_')[:20]}"
    for approval in approvals:
        if approval.get("approval_id") == approval_id:
            return approval
    approval = {
        "approval_id": approval_id,
        "status": "pending",
        "room_id": room_id,
        "task_id": task_id,
        "requester_node_id": requester_node_id,
        "runbook": runbook,
        "payload": redact_value(payload),
        "reason": reason,
        "created_at": round(time.time(), 3),
        "decided_at": None,
    }
    approvals.append(approval)
    save_approvals(home, approvals)
    return approval


def decide_approval(home: Path | None, approval_id: str, *, approved: bool) -> dict[str, Any]:
    approvals = load_approvals(home)
    for approval in approvals:
        if approval.get("approval_id") == approval_id:
            approval["status"] = "approved" if approved else "rejected"
            approval["decided_at"] = round(time.time(), 3)
            save_approvals(home, approvals)
            return approval
    raise KeyError(f"Unknown GremlinChat approval: {approval_id}")


def approval_for_task(home: Path | None, task_id: str) -> dict[str, Any] | None:
    for approval in load_approvals(home):
        if approval.get("task_id") == task_id:
            return approval
    return None


def mark_approval_consumed(home: Path | None, approval_id: str) -> None:
    approvals = load_approvals(home)
    for approval in approvals:
        if approval.get("approval_id") == approval_id:
            approval["status"] = "consumed"
            approval["consumed_at"] = round(time.time(), 3)
            save_approvals(home, approvals)
            return


def write_task_report(home: Path | None, report: dict[str, Any]) -> dict[str, str]:
    safe_report = redact_value(report)
    task_id = str(safe_report.get("task_id") or safe_report.get("result", {}).get("task_id") or "unknown")
    reports_dir = ensure_home(home) / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    json_path = reports_dir / f"{task_id}.json"
    md_path = reports_dir / f"{task_id}.md"
    json_path.write_text(json.dumps(safe_report, indent=2, sort_keys=True), encoding="utf-8")
    md_path.write_text(_markdown_report(safe_report), encoding="utf-8")
    return {"json": str(json_path), "markdown": str(md_path)}


def _markdown_report(report: dict[str, Any]) -> str:
    result = report.get("result", {})
    task_id = report.get("task_id", result.get("task_id", "unknown"))
    runbook = report.get("runbook", result.get("runbook", "unknown"))
    status = result.get("status", report.get("status", "unknown"))
    summary = result.get("summary", report.get("summary", ""))
    accepted = result.get("accepted", report.get("accepted", ""))
    return "\n".join(
        [
            f"# GremlinChat Task Report: {task_id}",
            "",
            f"- Runbook: `{runbook}`",
            f"- Status: `{status}`",
            f"- Accepted: `{accepted}`",
            f"- Summary: {summary}",
            "",
            "## JSON",
            "",
            "```json",
            json.dumps(report, indent=2, sort_keys=True),
            "```",
            "",
        ]
    )

