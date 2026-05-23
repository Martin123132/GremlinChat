"""Installer and local runtime readiness checks."""

from __future__ import annotations

import importlib.metadata
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from . import PRODUCT_NAME, PROTOCOL_VERSION
from .crypto import protect_secret, unprotect_secret
from .redaction import redact_value
from .runbooks import runbook_catalog
from .store import (
    append_audit_event,
    ensure_home,
    load_or_create_dashboard_token,
    load_or_create_identity,
    load_or_create_x25519_identity,
    load_policy,
)


def run_install_doctor(home: Path) -> dict[str, Any]:
    home = ensure_home(home)
    checks: list[dict[str, Any]] = []

    def add(name: str, status: str, summary: str, detail: Any | None = None, *, required: bool = True) -> None:
        checks.append(
            {
                "name": name,
                "status": status,
                "required": required,
                "summary": summary,
                "detail": redact_value(detail),
            }
        )

    add(
        "python",
        "pass" if sys.version_info >= (3, 11) else "fail",
        f"Python {sys.version.split()[0]}",
        {"executable": sys.executable},
    )
    _add_git_check(add)
    _add_package_check(add)
    _add_cli_check(add)
    _add_home_writable_check(add, home)
    _add_secret_protection_check(add)
    _add_identity_check(add, home)
    _add_dashboard_token_check(add, home)
    _add_reports_writable_check(add, home)
    _add_policy_check(add, home)
    _add_windows_install_checks(add)

    fail_count = len([check for check in checks if check["status"] == "fail"])
    warning_count = len([check for check in checks if check["status"] == "warning"])
    report = {
        "schema": "gremlinchat.install-doctor.v1",
        "ok": fail_count == 0,
        "created_at": round(time.time(), 3),
        "product": PRODUCT_NAME,
        "protocol_version": PROTOCOL_VERSION,
        "home": str(home),
        "summary": f"{fail_count} failed checks, {warning_count} warnings.",
        "checks": checks,
    }
    append_audit_event(home, {"event_type": "install.doctor", "ok": report["ok"], "summary": report["summary"]})
    return report


def write_install_doctor_report(home: Path, report: dict[str, Any]) -> dict[str, str]:
    home = ensure_home(home)
    safe_report = redact_value(report)
    reports_dir = home / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    suffix = uuid.uuid4().hex[:8]
    json_path = reports_dir / f"install-doctor-{stamp}-{suffix}.json"
    md_path = reports_dir / f"install-doctor-{stamp}-{suffix}.md"
    json_path.write_text(json.dumps(safe_report, indent=2, sort_keys=True), encoding="utf-8")
    md_path.write_text(_doctor_markdown(safe_report), encoding="utf-8")
    append_audit_event(home, {"event_type": "install.doctor_report", "json": str(json_path), "markdown": str(md_path)})
    return {"json": str(json_path), "markdown": str(md_path)}


def _add_git_check(add: Any) -> None:
    git_path = shutil.which("git")
    if not git_path:
        add("git", "fail", "git was not found on PATH.")
        return
    result = subprocess.run(["git", "--version"], check=False, capture_output=True, text=True, timeout=5)
    add(
        "git",
        "pass" if result.returncode == 0 else "fail",
        (result.stdout or result.stderr).strip() or "git command returned no version.",
        {"path": git_path},
    )


def _add_package_check(add: Any) -> None:
    try:
        version = importlib.metadata.version("gremlinchat")
    except importlib.metadata.PackageNotFoundError:
        version = "editable-or-local"
    add(
        "package",
        "pass",
        "GremlinChat package imports successfully.",
        {"name": PRODUCT_NAME, "version": version, "protocol_version": PROTOCOL_VERSION},
    )


def _add_cli_check(add: Any) -> None:
    cli_path = shutil.which("gremlinchat")
    if cli_path:
        add("cli", "pass", "gremlinchat command is available on PATH.", {"path": cli_path})
    else:
        add("cli", "warning", "gremlinchat command is not on PATH; installer venv shortcut may still work.", required=False)


def _add_home_writable_check(add: Any, home: Path) -> None:
    marker = home / ".install-doctor-write-test"
    try:
        marker.write_text("ok", encoding="utf-8")
        marker.unlink(missing_ok=True)
        add("home_writable", "pass", "GremlinChat home is writable.", {"home": str(home)})
    except OSError as exc:
        add("home_writable", "fail", f"GremlinChat home is not writable: {exc}", {"home": str(home)})


def _add_secret_protection_check(add: Any) -> None:
    try:
        protected = protect_secret("gremlinchat-install-doctor")
        ok = unprotect_secret(protected) == "gremlinchat-install-doctor"
        protection = protected.split(":", 1)[0]
        if not ok:
            add("secret_protection", "fail", "Local secret protection did not round-trip.", {"format": protection})
        elif sys.platform == "win32" and protection != "dpapi":
            add("secret_protection", "fail", "Windows secret protection is not using DPAPI.", {"format": protection})
        elif protection != "dpapi":
            add("secret_protection", "warning", "Secrets are protected only by local file permissions on this platform.", {"format": protection}, required=False)
        else:
            add("secret_protection", "pass", "Windows DPAPI secret protection is working.", {"format": protection})
    except Exception as exc:
        add("secret_protection", "fail", f"Local secret protection failed: {exc}")


def _add_identity_check(add: Any, home: Path) -> None:
    try:
        identity = load_or_create_identity(home)
        x25519_identity = load_or_create_x25519_identity(home)
        signature = identity.sign(b"gremlinchat-install-doctor")
        add(
            "identity",
            "pass" if signature else "fail",
            "Local signing and pairing identities are present.",
            {"node_id": identity.node_id, "public_key": identity.public_key, "x25519_public_key": x25519_identity.public_key},
        )
    except Exception as exc:
        add("identity", "fail", f"Could not create or load local identity: {exc}")


def _add_dashboard_token_check(add: Any, home: Path) -> None:
    try:
        token = load_or_create_dashboard_token(home)
        add("dashboard_token", "pass" if len(token) >= 24 else "fail", "Dashboard CSRF token exists.", {"token_length": len(token)})
    except Exception as exc:
        add("dashboard_token", "fail", f"Could not create dashboard token: {exc}")


def _add_reports_writable_check(add: Any, home: Path) -> None:
    reports_dir = home / "reports"
    marker = reports_dir / ".install-doctor-report-test"
    try:
        reports_dir.mkdir(parents=True, exist_ok=True)
        marker.write_text("ok", encoding="utf-8")
        marker.unlink(missing_ok=True)
        add("reports_writable", "pass", "Reports directory is writable.", {"path": str(reports_dir)})
    except OSError as exc:
        add("reports_writable", "fail", f"Reports directory is not writable: {exc}", {"path": str(reports_dir)})


def _add_policy_check(add: Any, home: Path) -> None:
    policy = load_policy(home)
    add(
        "read_only_lock",
        "pass" if policy.trial_read_only_lock else "warning",
        "Trial read-only lock is enabled." if policy.trial_read_only_lock else "Trial read-only lock is off; enable it before live trials.",
        {"enabled_write_runbooks": policy.enabled_write_runbooks},
        required=False,
    )
    add(
        "emergency_stop",
        "warning" if policy.emergency_stop else "pass",
        "Emergency stop is active." if policy.emergency_stop else "Emergency stop is off.",
        required=False,
    )
    add("runbook_policy", "pass", "Runbook policy can be loaded.", runbook_catalog(policy))


def _add_windows_install_checks(add: Any) -> None:
    if sys.platform != "win32":
        add("windows_installer", "warning", "Windows installer shortcut checks are skipped on this platform.", required=False)
        return
    local_app_data = os.environ.get("LOCALAPPDATA")
    app_data = os.environ.get("APPDATA")
    if not local_app_data or not app_data:
        add("windows_installer", "warning", "LOCALAPPDATA or APPDATA is not set, so installer paths cannot be checked.", required=False)
        return
    gremlin_root = Path(local_app_data) / "GremlinChat"
    gremlin_exe = gremlin_root / ".venv" / "Scripts" / "gremlinchat.exe"
    start_menu = Path(app_data) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "GremlinChat"
    expected_shortcuts = [
        "GremlinChat Dashboard.lnk",
        "GremlinChat Trial Listener.lnk",
        "GremlinChat Preflight.lnk",
        "GremlinChat Emergency Stop.lnk",
        "GremlinChat Install Doctor.lnk",
    ]
    missing_shortcuts = [name for name in expected_shortcuts if not (start_menu / name).exists()]
    add(
        "windows_venv",
        "pass" if gremlin_exe.exists() else "warning",
        "Installer venv command exists." if gremlin_exe.exists() else "Installer venv command was not found.",
        {"path": str(gremlin_exe)},
        required=False,
    )
    add(
        "windows_shortcuts",
        "pass" if not missing_shortcuts else "warning",
        "Start Menu shortcuts exist." if not missing_shortcuts else "Some Start Menu shortcuts are missing.",
        {"start_menu": str(start_menu), "missing": missing_shortcuts},
        required=False,
    )


def _doctor_markdown(report: dict[str, Any]) -> str:
    checks = report.get("checks", [])
    check_lines = [f"- `{check.get('status')}` {check.get('name')}: {check.get('summary')}" for check in checks]
    return "\n".join(
        [
            "# GremlinChat Install Doctor",
            "",
            f"- Status: `{report.get('ok')}`",
            f"- Summary: {report.get('summary', '')}",
            f"- Home: `{report.get('home', '')}`",
            "",
            "## Checks",
            "",
            *(check_lines or ["- No checks recorded."]),
            "",
            "## JSON",
            "",
            "```json",
            json.dumps(report, indent=2, sort_keys=True),
            "```",
            "",
        ]
    )
