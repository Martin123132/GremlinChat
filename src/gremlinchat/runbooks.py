"""Strict runbook executor. GremlinChat v0.1 never accepts arbitrary shell."""

from __future__ import annotations

import json
import platform
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .redaction import redact_value
from .store import ApprovedRepo, RunbookPolicy, append_audit_event

READ_RUNBOOKS = {"presence.ping", "machine.status", "repo.status", "worker.status", "gremlinchat.doctor"}
WRITE_RUNBOOKS = {"repo.pull_ff_only", "worker.restart_named", "tests.run_allowlisted"}
ALL_RUNBOOKS = READ_RUNBOOKS | WRITE_RUNBOOKS


@dataclass(frozen=True)
class RunbookResult:
    accepted: bool
    runbook: str
    status: str
    summary: str
    output: dict[str, Any]
    started_at: float
    completed_at: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "runbook": self.runbook,
            "status": self.status,
            "summary": self.summary,
            "output": redact_value(self.output),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


@dataclass(frozen=True)
class ApprovalCheck:
    status: str
    reason: str


def check_runbook_approval(
    runbook: str,
    payload: dict[str, Any] | None,
    *,
    policy: RunbookPolicy,
    requester_node_id: str | None = None,
) -> ApprovalCheck:
    payload = {} if payload is None else payload
    try:
        _authorize_base(runbook, policy, requester_node_id=requester_node_id)
        repo = _approved_repo(payload, policy) if runbook.startswith("repo.") or runbook == "tests.run_allowlisted" else None
        if runbook in READ_RUNBOOKS:
            return ApprovalCheck("auto", "Read-only runbook may run automatically.")
        if runbook == "repo.pull_ff_only":
            if runbook in policy.enabled_write_runbooks and repo is not None and repo.allow_pull_ff_only:
                return ApprovalCheck("auto", "Fast-forward pull is pre-approved for this repo.")
            return ApprovalCheck("pending", "Fast-forward pull needs local owner approval.")
        if runbook == "worker.restart_named":
            name = str(payload.get("worker_name", ""))
            if name not in policy.managed_workers:
                return ApprovalCheck("reject", f"Worker {name!r} is not managed by GremlinChat.")
            if runbook in policy.enabled_write_runbooks:
                return ApprovalCheck("auto", "Worker restart is pre-approved.")
            return ApprovalCheck("pending", "Worker restart needs local owner approval.")
        if runbook == "tests.run_allowlisted":
            test_name = str(payload.get("test_name", ""))
            if test_name not in policy.allowlisted_tests:
                return ApprovalCheck("reject", f"Test {test_name!r} is not allowlisted.")
            if runbook in policy.enabled_write_runbooks and repo is not None and test_name in repo.allow_tests:
                return ApprovalCheck("auto", "Allowlisted test is pre-approved for this repo.")
            return ApprovalCheck("pending", "Allowlisted test needs local owner approval.")
        return ApprovalCheck("reject", f"Runbook {runbook!r} is not available.")
    except PermissionError as exc:
        return ApprovalCheck("reject", str(exc))


def execute_runbook(
    runbook: str,
    payload: dict[str, Any] | None,
    *,
    policy: RunbookPolicy,
    home: Path | None = None,
    requester_node_id: str | None = None,
    approval_override: bool = False,
) -> RunbookResult:
    payload = {} if payload is None else payload
    started_at = round(time.time(), 3)
    try:
        _authorize(runbook, payload, policy, requester_node_id=requester_node_id, approval_override=approval_override)
        if runbook == "presence.ping":
            return _result(True, runbook, "completed", "Presence ping completed.", {"pong": True, "server_time": round(time.time(), 3)}, started_at, home)
        if runbook == "machine.status":
            return _result(True, runbook, "completed", "Machine status collected.", _machine_status(), started_at, home)
        if runbook == "repo.status":
            repo = _approved_repo(payload, policy)
            return _result(True, runbook, "completed", f"Repo status collected for {repo.name}.", _repo_status(Path(repo.path)), started_at, home)
        if runbook == "worker.status":
            output = {"managed_workers": sorted(policy.managed_workers), "worker_count": len(policy.managed_workers)}
            return _result(True, runbook, "completed", "Worker status collected.", output, started_at, home)
        if runbook == "gremlinchat.doctor":
            output = _doctor_report(home)
            return _result(True, runbook, "completed", "GremlinChat doctor completed.", output, started_at, home)
        if runbook == "repo.pull_ff_only":
            repo = _approved_repo(payload, policy)
            if not approval_override and not repo.allow_pull_ff_only:
                raise PermissionError(f"Fast-forward pulls are not enabled for repo {repo.name!r}.")
            return _result(True, runbook, "completed", f"Fast-forward pull completed for {repo.name}.", _repo_pull_ff_only(Path(repo.path)), started_at, home)
        if runbook == "worker.restart_named":
            name = str(payload.get("worker_name", ""))
            command = policy.managed_workers.get(name)
            if not command:
                raise PermissionError(f"Worker {name!r} is not managed by GremlinChat.")
            return _result(True, runbook, "completed", f"Restart command ran for {name}.", _run_command(command, cwd=None, timeout_seconds=30), started_at, home)
        if runbook == "tests.run_allowlisted":
            repo = _approved_repo(payload, policy)
            test_name = str(payload.get("test_name", ""))
            if not approval_override and test_name not in repo.allow_tests:
                raise PermissionError(f"Test {test_name!r} is not enabled for repo {repo.name!r}.")
            command = policy.allowlisted_tests.get(test_name)
            if not command:
                raise PermissionError(f"Test {test_name!r} is not allowlisted.")
            return _result(True, runbook, "completed", f"Allowlisted test ran: {test_name}.", _run_command(command, cwd=Path(repo.path), timeout_seconds=120), started_at, home)
        raise PermissionError(f"Runbook {runbook!r} is not available.")
    except Exception as exc:
        return _result(
            False,
            runbook,
            "rejected" if isinstance(exc, PermissionError | ValueError) else "failed",
            str(exc),
            {"error": str(exc), "error_type": type(exc).__name__},
            started_at,
            home,
        )


def runbook_catalog(policy: RunbookPolicy) -> dict[str, Any]:
    return {
        "read_runbooks": sorted(READ_RUNBOOKS),
        "write_runbooks": sorted(WRITE_RUNBOOKS),
        "enabled_write_runbooks": sorted(policy.enabled_write_runbooks),
        "approved_repos": [repo.to_dict() for repo in policy.approved_repos],
        "allowlisted_tests": sorted(policy.allowlisted_tests),
        "managed_workers": sorted(policy.managed_workers),
        "emergency_stop": policy.emergency_stop,
    }


def runbook_result_json(result: RunbookResult) -> str:
    return json.dumps(result.to_dict(), indent=2, sort_keys=True)


def _authorize(runbook: str, payload: dict[str, Any], policy: RunbookPolicy, *, requester_node_id: str | None, approval_override: bool = False) -> None:
    _authorize_base(runbook, policy, requester_node_id=requester_node_id)
    if runbook in WRITE_RUNBOOKS and not approval_override and runbook not in policy.enabled_write_runbooks:
        raise PermissionError(f"Write-capable runbook {runbook!r} is not enabled by the machine owner.")
    if runbook.startswith("repo.") or runbook == "tests.run_allowlisted":
        _approved_repo(payload, policy)


def _authorize_base(runbook: str, policy: RunbookPolicy, *, requester_node_id: str | None) -> None:
    if policy.emergency_stop:
        raise PermissionError("Emergency stop is active; remote runbooks are disabled.")
    if requester_node_id and requester_node_id in policy.revoked_node_ids:
        raise PermissionError("Requester has been revoked.")
    if runbook not in ALL_RUNBOOKS:
        raise PermissionError(f"Unknown or arbitrary command rejected: {runbook}")


def _approved_repo(payload: dict[str, Any], policy: RunbookPolicy) -> ApprovedRepo:
    repo_name = payload.get("repo")
    requested_path = payload.get("repo_path")
    if not repo_name and not requested_path:
        raise PermissionError("Repo runbooks require repo or repo_path.")
    for repo in policy.approved_repos:
        base = _resolved_path(repo.path)
        if repo_name and repo.name == repo_name:
            _reject_if_outside_base(requested_path or repo.path, base)
            return repo
        if requested_path and _resolved_path(str(requested_path)) == base:
            return repo
    raise PermissionError("Repo path is not approved for GremlinChat runbooks.")


def _reject_if_outside_base(path: str, base: Path) -> None:
    requested = _resolved_path(path)
    if requested != base and base not in requested.parents:
        raise PermissionError("Requested path escapes the approved repo.")


def _resolved_path(path: str | Path) -> Path:
    return Path(path).expanduser().resolve()


def _machine_status() -> dict[str, Any]:
    return {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python_version": platform.python_version(),
        "hostname": socket.gethostname(),
        "executable": sys.executable,
    }


def _doctor_report(home: Path | None) -> dict[str, Any]:
    return {
        "home": None if home is None else str(home),
        "python_version": platform.python_version(),
        "system": platform.system(),
        "git_available": _run_command(["git", "--version"], cwd=None, timeout_seconds=5)["returncode"] == 0,
    }


def _repo_status(path: Path) -> dict[str, Any]:
    branch = _git(path, "rev-parse", "--abbrev-ref", "HEAD", allow_failure=True)
    commit = _git(path, "rev-parse", "HEAD", allow_failure=True)
    status = _git(path, "status", "--short", "--branch", allow_failure=True)
    return {
        "repo_path": str(path),
        "branch": branch["stdout"].strip(),
        "commit": commit["stdout"].strip(),
        "status": status["stdout"].splitlines(),
        "clean": not bool(_git(path, "status", "--porcelain", allow_failure=True)["stdout"].strip()),
    }


def _repo_pull_ff_only(path: Path) -> dict[str, Any]:
    dirty = _git(path, "status", "--porcelain")
    if dirty["stdout"].strip():
        raise PermissionError("Refusing pull because the approved repo has local changes.")
    return _git(path, "pull", "--ff-only")


def _git(path: Path, *args: str, allow_failure: bool = False) -> dict[str, Any]:
    result = _run_command(["git", "-C", str(path), *args], cwd=None, timeout_seconds=30)
    if result["returncode"] != 0 and not allow_failure:
        raise RuntimeError(result["stderr"] or result["stdout"] or f"git {' '.join(args)} failed")
    return result


def _run_command(command: list[str], *, cwd: Path | None, timeout_seconds: int) -> dict[str, Any]:
    completed = subprocess.run(command, cwd=str(cwd) if cwd is not None else None, check=False, capture_output=True, text=True, timeout=timeout_seconds)
    return {
        "command": command,
        "cwd": None if cwd is None else str(cwd),
        "returncode": completed.returncode,
        "stdout": completed.stdout[-4000:],
        "stderr": completed.stderr[-4000:],
    }


def _result(accepted: bool, runbook: str, status: str, summary: str, output: dict[str, Any], started_at: float, home: Path | None) -> RunbookResult:
    completed_at = round(time.time(), 3)
    result = RunbookResult(accepted, runbook, status, summary, output, started_at, completed_at)
    append_audit_event(home, {"event_type": "runbook.result", "runbook": runbook, "accepted": accepted, "status": status, "summary": summary, "output": result.to_dict()["output"]})
    return result

