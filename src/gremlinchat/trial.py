"""Read-only trial checks and local end-to-end simulation."""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen

from .crypto import create_invite_code, parse_invite_code, protect_secret, safety_phrase, unprotect_secret
from .messages import create_pair_hello
from .redaction import redact_value
from .relay import RelayClient, create_relay_http_server
from .roomops import GremlinChatError, process_room_once, request_runbook, revoke_room, sync_room_messages, verify_room
from .runbooks import READ_RUNBOOKS, runbook_catalog
from .store import (
    append_audit_event,
    ensure_home,
    load_or_create_identity,
    load_or_create_x25519_identity,
    load_policy,
    load_rooms,
    read_audit_events,
    save_room,
)


TRIAL_RUNBOOKS = ["presence.ping", "machine.status", "gremlinchat.doctor"]


def run_preflight(
    home: Path,
    *,
    relay_url: str | None = None,
    dashboard_port: int = 8777,
    relay_port: int = 8778,
) -> dict[str, Any]:
    home = ensure_home(home)
    identity = load_or_create_identity(home)
    load_or_create_x25519_identity(home)
    policy = load_policy(home)
    rooms = load_rooms(home)
    checks: list[dict[str, Any]] = []

    def add(name: str, status: str, summary: str, detail: Any | None = None) -> None:
        checks.append({"name": name, "status": status, "summary": summary, "detail": redact_value(detail)})

    add("python", "pass" if sys.version_info >= (3, 11) else "fail", f"Python {sys.version.split()[0]}", {"executable": sys.executable})
    git_path = shutil.which("git")
    if git_path:
        git_version = subprocess.run(["git", "--version"], check=False, capture_output=True, text=True, timeout=5)
        add("git", "pass" if git_version.returncode == 0 else "fail", (git_version.stdout or git_version.stderr).strip(), {"path": git_path})
    else:
        add("git", "fail", "git was not found on PATH")

    try:
        protected = protect_secret("gremlinchat-preflight-secret")
        round_trip = unprotect_secret(protected) == "gremlinchat-preflight-secret"
        status = "pass" if round_trip and (sys.platform != "win32" or protected.startswith("dpapi:")) else "fail"
        add("secret_protection", status, "Local secret protection round-trip completed.", {"format": protected.split(":", 1)[0]})
    except Exception as exc:
        add("secret_protection", "fail", str(exc))

    add("identity", "pass", "Local GremlinChat identity is present.", {"node_id": identity.node_id, "public_key": identity.public_key})
    add("dashboard_port", "pass" if _port_available(dashboard_port) else "warning", f"127.0.0.1:{dashboard_port} {'is available' if _port_available(dashboard_port) else 'is already in use'}")
    add("relay_port", "pass" if _port_available(relay_port) else "warning", f"127.0.0.1:{relay_port} {'is available' if _port_available(relay_port) else 'is already in use'}")

    if relay_url:
        add("relay_reachability", *_relay_check(relay_url))
    else:
        add("relay_reachability", "warning", "No relay URL supplied. Use --relay http://LAN_OR_TAILSCALE_IP:8778 for the live trial.")

    room_detail = [_room_summary(room) for room in rooms]
    if not rooms:
        add("room_state", "warning", "No rooms are paired yet.", room_detail)
    elif any(room.get("verified") and not room.get("disabled") for room in rooms):
        add("room_state", "pass", "At least one room is verified and enabled.", room_detail)
    else:
        add("room_state", "warning", "Rooms exist, but none are currently verified and enabled.", room_detail)

    add("emergency_stop", "fail" if policy.emergency_stop else "pass", "Emergency stop is active." if policy.emergency_stop else "Emergency stop is off.")
    if policy.trial_read_only_lock:
        status = "warning" if policy.enabled_write_runbooks else "pass"
        add("read_only_trial_lock", status, "Write-capable runbooks are blocked by the trial read-only lock.", {"enabled_write_runbooks": policy.enabled_write_runbooks})
    else:
        add("read_only_trial_lock", "fail", "Trial read-only lock is off; turn it back on before the Martin/Glyn trial.", {"enabled_write_runbooks": policy.enabled_write_runbooks})

    redacted = json.dumps(redact_value({"relay_token": "secret-token", "line": "Bearer abcdefghijklmnopqrstuvwxyz123456"}), sort_keys=True)
    add("report_redaction", "pass" if "secret-token" not in redacted and "Bearer " not in redacted else "fail", "Report redaction removes relay tokens and bearer-style secrets.")

    ok = not any(check["status"] == "fail" for check in checks)
    return {
        "schema": "gremlinchat.trial-preflight.v1",
        "ok": ok,
        "created_at": round(time.time(), 3),
        "home": str(home),
        "node_id": identity.node_id,
        "relay_url": relay_url,
        "checks": checks,
        "rooms": room_detail,
        "policy": runbook_catalog(policy),
    }


def run_trial_simulation(*, write_report_home: Path | None = None) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="gremlinchat-trial-") as root_raw:
        root = Path(root_raw)
        alice_home = root / "alice"
        bob_home = root / "bob"
        relay_state = root / "relay-state"
        server = create_relay_http_server(host="127.0.0.1", port=0, state_dir=relay_state)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host, port = server.server_address
        relay_url = f"http://{host}:{port}"
        try:
            summary = _simulate_pairing_and_read_only_runbooks(alice_home, bob_home, relay_url)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        summary["relay_state_persisted"] = (relay_state / "relay.sqlite3").exists()
        if write_report_home is not None:
            summary["report_paths"] = write_trial_report(write_report_home, summary)
        return summary


def write_trial_report(home: Path, summary: dict[str, Any]) -> dict[str, str]:
    home = ensure_home(home)
    safe_summary = redact_value(summary)
    reports_dir = home / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    suffix = uuid.uuid4().hex[:8]
    json_path = reports_dir / f"trial-{stamp}-{suffix}.json"
    md_path = reports_dir / f"trial-{stamp}-{suffix}.md"
    json_path.write_text(json.dumps(safe_summary, indent=2, sort_keys=True), encoding="utf-8")
    md_path.write_text(_trial_markdown(safe_summary), encoding="utf-8")
    append_audit_event(home, {"event_type": "trial.report", "summary": safe_summary.get("summary", ""), "ok": safe_summary.get("ok")})
    return {"json": str(json_path), "markdown": str(md_path)}


def current_trial_snapshot(home: Path) -> dict[str, Any]:
    home = ensure_home(home)
    identity = load_or_create_identity(home)
    policy = load_policy(home)
    return {
        "schema": "gremlinchat.trial-report.v1",
        "ok": not policy.emergency_stop and policy.trial_read_only_lock,
        "created_at": round(time.time(), 3),
        "summary": "GremlinChat local trial snapshot.",
        "home": str(home),
        "node_id": identity.node_id,
        "rooms": [_room_summary(room) for room in load_rooms(home)],
        "policy": runbook_catalog(policy),
        "audit": read_audit_events(home, limit=25),
    }


def _simulate_pairing_and_read_only_runbooks(alice_home: Path, bob_home: Path, relay_url: str) -> dict[str, Any]:
    alice = load_or_create_identity(alice_home)
    alice_x = load_or_create_x25519_identity(alice_home)
    bob = load_or_create_identity(bob_home)
    bob_x = load_or_create_x25519_identity(bob_home)
    room_response = RelayClient(relay_url).create_room(ttl_seconds=600)
    invite_code = create_invite_code(
        creator=alice,
        creator_x25519_public_key=alice_x.public_key,
        relay_url=relay_url,
        room_id=room_response["room_id"],
        relay_token=room_response["relay_token"],
        ttl_seconds=600,
    )
    invite = parse_invite_code(invite_code)
    save_room(
        {
            "room_id": invite.room_id,
            "relay_url": invite.relay_url,
            "relay_token": invite.relay_token,
            "pair_secret": invite.pair_secret,
            "local_x25519_public_key": alice_x.public_key,
            "created_by": alice.node_id,
            "created_at": round(time.time(), 3),
            "expires_at": invite.expires_at,
            "verified": False,
            "disabled": False,
            "processed_message_ids": [],
        },
        alice_home,
    )
    phrase = safety_phrase(invite.pair_secret, [invite.creator_public_key, bob.public_key])
    save_room(
        {
            "room_id": invite.room_id,
            "relay_url": invite.relay_url,
            "relay_token": invite.relay_token,
            "pair_secret": invite.pair_secret,
            "peer_node_id": invite.creator_node_id,
            "peer_public_key": invite.creator_public_key,
            "peer_x25519_public_key": invite.creator_x25519_public_key,
            "local_x25519_public_key": bob_x.public_key,
            "joined_by": bob.node_id,
            "joined_at": round(time.time(), 3),
            "expires_at": invite.expires_at,
            "safety_phrase": phrase,
            "verified": False,
            "disabled": False,
            "processed_message_ids": [],
        },
        bob_home,
    )
    RelayClient(invite.relay_url).post_envelope(
        room_id=invite.room_id,
        relay_token=invite.relay_token,
        envelope=create_pair_hello(room_id=invite.room_id, sender=bob, x25519_public_key=bob_x.public_key),
    )
    alice_sync = sync_room_messages(alice_home, invite.room_id)
    verify_room(alice_home, invite.room_id, str(alice_sync["safety_phrase"]))
    verify_room(bob_home, invite.room_id, phrase)

    runbook_results = []
    for runbook in TRIAL_RUNBOOKS:
        request = request_runbook(alice_home, invite.room_id, runbook, {})
        processed = process_room_once(bob_home, invite.room_id)
        synced = sync_room_messages(alice_home, invite.room_id)
        result_messages = [message for message in synced["decrypted_messages"] if message.get("type") == "task.result.v1" and message.get("task_id") == request["task_id"]]
        runbook_results.append(
            {
                "runbook": runbook,
                "task_id": request["task_id"],
                "processed_count": processed["count"],
                "result_status": result_messages[-1]["result"]["status"] if result_messages else "missing",
                "result_accepted": result_messages[-1]["result"]["accepted"] if result_messages else False,
            }
        )

    revoke = revoke_room(alice_home, invite.room_id)
    blocked_after_revoke = False
    try:
        request_runbook(alice_home, invite.room_id, "presence.ping", {})
    except GremlinChatError:
        blocked_after_revoke = True

    ok = all(result["result_accepted"] for result in runbook_results) and blocked_after_revoke
    return {
        "schema": "gremlinchat.trial-simulation.v1",
        "ok": ok,
        "summary": "Local two-client read-only trial completed." if ok else "Local two-client read-only trial failed.",
        "created_at": round(time.time(), 3),
        "relay_url": relay_url,
        "alice_node_id": alice.node_id,
        "bob_node_id": bob.node_id,
        "room_id": invite.room_id,
        "safety_phrase": alice_sync["safety_phrase"],
        "read_only_runbooks": TRIAL_RUNBOOKS,
        "available_read_runbooks": sorted(READ_RUNBOOKS),
        "runbook_results": runbook_results,
        "revoke_result": revoke,
        "blocked_after_revoke": blocked_after_revoke,
    }


def _port_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def _relay_check(relay_url: str) -> tuple[str, str, Any]:
    try:
        with urlopen(relay_url.rstrip("/") + "/health", timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return ("pass", "Relay health endpoint is reachable.", payload)
    except (OSError, URLError, json.JSONDecodeError) as exc:
        return ("fail", f"Relay is not reachable: {exc}", None)


def _room_summary(room: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in room.items()
        if key not in {"relay_token", "relay_token_protected", "pair_secret", "pair_secret_protected"}
    }


def _trial_markdown(summary: dict[str, Any]) -> str:
    checks = summary.get("checks", [])
    check_lines = [f"- `{check.get('status')}` {check.get('name')}: {check.get('summary')}" for check in checks]
    runbook_lines = [
        f"- `{item.get('runbook')}`: `{item.get('result_status')}` accepted=`{item.get('result_accepted')}`"
        for item in summary.get("runbook_results", [])
    ]
    return "\n".join(
        [
            "# GremlinChat Trial Report",
            "",
            f"- Status: `{summary.get('ok')}`",
            f"- Summary: {summary.get('summary', '')}",
            f"- Created: `{summary.get('created_at', '')}`",
            "",
            "## Checks",
            "",
            *(check_lines or ["- No checks recorded."]),
            "",
            "## Read-Only Runbooks",
            "",
            *(runbook_lines or ["- No runbook results recorded."]),
            "",
            "## JSON",
            "",
            "```json",
            json.dumps(summary, indent=2, sort_keys=True),
            "```",
            "",
        ]
    )
