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
from typing import Any, Callable
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
    load_approvals,
    load_or_create_identity,
    load_or_create_x25519_identity,
    load_policy,
    load_rooms,
    read_audit_events,
    save_policy,
    save_room,
)


TRIAL_RUNBOOKS = ["presence.ping", "machine.status", "gremlinchat.doctor"]
RESET_CONFIRMATION = "RESET-GREMLINCHAT-TRIAL"


def create_trial_invite(home: Path, *, relay_url: str, ttl_seconds: int = 600) -> dict[str, Any]:
    home = ensure_home(home)
    identity = load_or_create_identity(home)
    x25519_identity = load_or_create_x25519_identity(home)
    room_response = RelayClient(relay_url).create_room(ttl_seconds=ttl_seconds)
    if "room_id" not in room_response:
        raise GremlinChatError(f"relay room creation failed: {room_response}")
    invite_code = create_invite_code(
        creator=identity,
        creator_x25519_public_key=x25519_identity.public_key,
        relay_url=relay_url,
        room_id=room_response["room_id"],
        relay_token=room_response["relay_token"],
        ttl_seconds=ttl_seconds,
    )
    invite = parse_invite_code(invite_code)
    save_room(
        {
            "room_id": invite.room_id,
            "relay_url": invite.relay_url,
            "relay_token": invite.relay_token,
            "pair_secret": invite.pair_secret,
            "local_x25519_public_key": x25519_identity.public_key,
            "created_by": identity.node_id,
            "created_at": round(time.time(), 3),
            "expires_at": invite.expires_at,
            "verified": False,
            "disabled": False,
            "processed_message_ids": [],
        },
        home,
    )
    result = {
        "schema": "gremlinchat.trial-host.v1",
        "room_id": invite.room_id,
        "relay_url": invite.relay_url,
        "expires_at": invite.expires_at,
        "invite_code": invite_code,
        "next_steps": [
            "Share the invite code privately.",
            "Ask the guest to run gremlinchat trial guest GC1:...",
            "Run gremlinchat room sync, compare the safety phrase out of band, then run gremlinchat room verify --phrase <phrase>.",
            "After both sides verify, ask the guest to run gremlinchat trial listen and run gremlinchat trial prove.",
        ],
    }
    append_audit_event(home, {"event_type": "trial.host_invite_created", "room_id": invite.room_id, "relay_url": invite.relay_url, "expires_at": invite.expires_at})
    return result


def accept_trial_invite(home: Path, code: str) -> dict[str, Any]:
    home = ensure_home(home)
    identity = load_or_create_identity(home)
    x25519_identity = load_or_create_x25519_identity(home)
    invite = parse_invite_code(code)
    phrase = safety_phrase(invite.pair_secret, [invite.creator_public_key, identity.public_key])
    save_room(
        {
            "room_id": invite.room_id,
            "relay_url": invite.relay_url,
            "relay_token": invite.relay_token,
            "pair_secret": invite.pair_secret,
            "peer_node_id": invite.creator_node_id,
            "peer_public_key": invite.creator_public_key,
            "peer_x25519_public_key": invite.creator_x25519_public_key,
            "local_x25519_public_key": x25519_identity.public_key,
            "joined_by": identity.node_id,
            "joined_at": round(time.time(), 3),
            "expires_at": invite.expires_at,
            "safety_phrase": phrase,
            "verified": False,
            "disabled": False,
            "processed_message_ids": [],
        },
        home,
    )
    hello_response = RelayClient(invite.relay_url).post_envelope(
        room_id=invite.room_id,
        relay_token=invite.relay_token,
        envelope=create_pair_hello(room_id=invite.room_id, sender=identity, x25519_public_key=x25519_identity.public_key),
    )
    result = {
        "schema": "gremlinchat.trial-guest.v1",
        "joined": True,
        "room_id": invite.room_id,
        "relay_url": invite.relay_url,
        "peer_node_id": invite.creator_node_id,
        "safety_phrase": phrase,
        "hello_posted": hello_response.get("accepted") is True,
        "next_steps": [
            "Compare this safety phrase with the host out of band.",
            "Run gremlinchat room verify --phrase <phrase> only if both sides match.",
            "After both sides verify, run gremlinchat trial listen so the host can run gremlinchat trial prove.",
        ],
    }
    append_audit_event(home, {"event_type": "trial.guest_invite_accepted", "room_id": invite.room_id, "peer_node_id": invite.creator_node_id, "hello_response": hello_response})
    return result


def run_live_read_only_proof(
    home: Path,
    *,
    room_id: str | None = None,
    timeout_seconds: float = 30.0,
    poll_interval: float = 2.0,
    write_report: bool = True,
    process_once: Callable[[], Any] | None = None,
) -> dict[str, Any]:
    home = ensure_home(home)
    started_at = round(time.time(), 3)
    sent = [request_runbook(home, room_id, runbook, {}) for runbook in TRIAL_RUNBOOKS]
    expected = {item["task_id"]: runbook for item, runbook in zip(sent, TRIAL_RUNBOOKS, strict=True)}
    results: dict[str, dict[str, Any]] = {}
    deadline = time.monotonic() + timeout_seconds
    syncs = []
    while time.monotonic() <= deadline and len(results) < len(expected):
        if process_once is not None:
            process_once()
        sync = sync_room_messages(home, room_id)
        syncs.append({"message_count": sync["message_count"], "decrypted_count": len(sync["decrypted_messages"])})
        for message in sync["decrypted_messages"]:
            if message.get("type") != "task.result.v1":
                continue
            task_id = str(message.get("task_id", ""))
            if task_id in expected:
                results[task_id] = message
        if len(results) >= len(expected):
            break
        if poll_interval > 0:
            time.sleep(poll_interval)
    runbook_results = []
    for task_id, runbook in expected.items():
        message = results.get(task_id)
        result = {} if message is None else dict(message.get("result", {}))
        runbook_results.append(
            {
                "runbook": runbook,
                "task_id": task_id,
                "result_status": result.get("status", "missing"),
                "result_accepted": bool(result.get("accepted", False)),
                "summary": result.get("summary", "No result returned before timeout."),
            }
        )
    ok = len(results) == len(expected) and all(item["result_accepted"] for item in runbook_results)
    report = {
        "schema": "gremlinchat.live-readonly-proof.v1",
        "ok": ok,
        "summary": "Live read-only proof completed." if ok else "Live read-only proof did not receive every expected result.",
        "started_at": started_at,
        "completed_at": round(time.time(), 3),
        "timeout_seconds": timeout_seconds,
        "read_only_runbooks": TRIAL_RUNBOOKS,
        "sent_tasks": sent,
        "runbook_results": runbook_results,
        "syncs": syncs,
    }
    if write_report:
        report["report_paths"] = write_trial_report(home, report)
    append_audit_event(home, {"event_type": "trial.live_readonly_proof", "ok": ok, "runbook_results": runbook_results})
    return report


def enforce_trial_read_only_lock(home: Path) -> dict[str, Any]:
    home = ensure_home(home)
    policy = load_policy(home)
    changed = False
    if not policy.trial_read_only_lock:
        policy.trial_read_only_lock = True
        save_policy(policy, home)
        changed = True
        append_audit_event(home, {"event_type": "trial.read_only_lock_enabled"})
    return {"trial_read_only_lock": True, "changed": changed}


def listen_once(home: Path, *, room_id: str | None = None) -> dict[str, Any]:
    lock = enforce_trial_read_only_lock(home)
    processed = process_room_once(home, room_id)
    return {"read_only_lock": lock, **processed}


def build_trial_checklist(home: Path, *, role: str, relay_url: str | None = None) -> dict[str, Any]:
    home = ensure_home(home)
    role = role.lower().strip()
    if role not in {"host", "guest"}:
        raise GremlinChatError("Trial checklist role must be host or guest.")
    policy = load_policy(home)
    rooms = load_rooms(home)
    active_rooms = [room for room in rooms if not room.get("disabled")]
    verified_rooms = [room for room in active_rooms if room.get("verified")]
    unverified_rooms = [room for room in active_rooms if not room.get("verified")]
    revoked_rooms = [room for room in rooms if room.get("peer_node_id") in policy.revoked_node_ids or room.get("revoked_at")]
    commands: list[str] = []
    next_steps: list[str] = []
    warnings: list[str] = []

    if policy.emergency_stop:
        warnings.append("Emergency stop is active. Run a local reset or manually clear it only if you intend to continue.")
    if not policy.trial_read_only_lock:
        warnings.append("Read-only trial lock is off. Run gremlinchat trial listen or gremlinchat trial preflight before processing requests.")

    if role == "host":
        if not rooms:
            if relay_url:
                commands.append(f"gremlinchat trial host --relay {relay_url}")
                next_steps.append("Share the GC1 invite privately, then wait for the guest to join.")
            else:
                commands.append("gremlinchat trial preflight --relay http://YOUR_LAN_OR_TAILSCALE_IP:8778 --write-report")
                commands.append("gremlinchat trial host --relay http://YOUR_LAN_OR_TAILSCALE_IP:8778")
                next_steps.append("Start or choose the private relay, then create the host invite.")
        elif unverified_rooms:
            commands.append("gremlinchat room sync")
            phrase = str(unverified_rooms[0].get("safety_phrase") or "WORD-WORD-WORD-WORD")
            commands.append(f"gremlinchat room verify --phrase {phrase}")
            next_steps.append("Compare the safety phrase out of band before running verify.")
        elif verified_rooms:
            commands.append("gremlinchat trial prove")
            commands.append("gremlinchat trial bundle")
            next_steps.append("Ask the guest to run gremlinchat trial listen, then run the proof.")
        else:
            commands.append("gremlinchat trial reset-local --confirm RESET-GREMLINCHAT-TRIAL")
            next_steps.append("All known rooms are disabled or revoked; reset locally before creating a new trial.")
    else:
        if not rooms:
            commands.append("gremlinchat trial guest GC1:...")
            next_steps.append("Paste only an invite code received privately from the host.")
        elif unverified_rooms:
            phrase = str(unverified_rooms[0].get("safety_phrase") or "WORD-WORD-WORD-WORD")
            commands.append(f"gremlinchat room verify --phrase {phrase}")
            next_steps.append("Compare this safety phrase with the host out of band before verifying.")
        elif verified_rooms:
            commands.append("gremlinchat trial listen")
            commands.append("gremlinchat trial bundle")
            next_steps.append("Keep the listener running while the host runs gremlinchat trial prove.")
        else:
            commands.append("gremlinchat trial reset-local --confirm RESET-GREMLINCHAT-TRIAL")
            next_steps.append("All known rooms are disabled or revoked; reset locally before joining a fresh invite.")

    return {
        "schema": "gremlinchat.trial-checklist.v1",
        "role": role,
        "ok": not policy.emergency_stop and policy.trial_read_only_lock,
        "relay_url": relay_url,
        "room_count": len(rooms),
        "verified_room_count": len(verified_rooms),
        "revoked_room_count": len(revoked_rooms),
        "emergency_stop": policy.emergency_stop,
        "trial_read_only_lock": policy.trial_read_only_lock,
        "commands": commands,
        "next_steps": next_steps,
        "warnings": warnings,
        "rooms": [_room_summary(room) for room in rooms],
    }


def trial_status(home: Path, *, relay_url: str | None = None) -> dict[str, Any]:
    home = ensure_home(home)
    identity = load_or_create_identity(home)
    policy = load_policy(home)
    rooms = [_room_summary(room) for room in load_rooms(home)]
    preflight = run_preflight(home, relay_url=relay_url)
    latest_proof = _latest_report_summary(home, schema="gremlinchat.live-readonly-proof.v1")
    return {
        "schema": "gremlinchat.trial-status.v1",
        "ok": preflight["ok"],
        "created_at": round(time.time(), 3),
        "node_id": identity.node_id,
        "verified_room_count": len([room for room in rooms if room.get("verified") and not room.get("disabled")]),
        "room_count": len(rooms),
        "trial_read_only_lock": policy.trial_read_only_lock,
        "emergency_stop": policy.emergency_stop,
        "latest_proof": latest_proof,
        "preflight": preflight,
        "rooms": rooms,
    }


def write_trial_bundle(home: Path, *, relay_url: str | None = None) -> dict[str, str]:
    home = ensure_home(home)
    bundle = _sanitize_bundle(
        home,
        {
            "schema": "gremlinchat.trial-bundle.v1",
            "created_at": round(time.time(), 3),
            "home": str(home),
            "preflight": run_preflight(home, relay_url=relay_url),
            "rooms": [_room_summary(room) for room in load_rooms(home)],
            "policy": _policy_for_bundle(load_policy(home)),
            "approvals": load_approvals(home),
            "audit": read_audit_events(home, limit=50),
            "reports": _reports_index(home),
            "versions": _version_summary(),
            "relay_health": None if relay_url is None else _relay_health_payload(relay_url),
        },
    )
    reports_dir = home / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    suffix = uuid.uuid4().hex[:8]
    json_path = reports_dir / f"bundle-{stamp}-{suffix}.json"
    md_path = reports_dir / f"bundle-{stamp}-{suffix}.md"
    json_path.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")
    md_path.write_text(_bundle_markdown(bundle), encoding="utf-8")
    append_audit_event(home, {"event_type": "trial.bundle", "json": str(json_path), "markdown": str(md_path)})
    return {"json": str(json_path), "markdown": str(md_path)}


def reset_local_trial(home: Path, *, confirm: str) -> dict[str, Any]:
    if confirm != RESET_CONFIRMATION:
        raise GremlinChatError(f"Refusing reset without --confirm {RESET_CONFIRMATION}.")
    home = ensure_home(home)
    identity = load_or_create_identity(home)
    policy = load_policy(home)
    revoked_node_ids = list(policy.revoked_node_ids)
    removed: list[str] = []
    for filename in ["rooms.json", "approvals.json"]:
        path = home / filename
        if path.exists():
            path.unlink()
            removed.append(filename)
    reports_dir = home / "reports"
    if reports_dir.exists():
        shutil.rmtree(reports_dir)
        removed.append("reports")
    policy.emergency_stop = False
    policy.trial_read_only_lock = True
    policy.revoked_node_ids = revoked_node_ids
    save_policy(policy, home)
    append_audit_event(home, {"event_type": "trial.reset_local", "removed": removed, "preserved_node_id": identity.node_id})
    return {
        "reset": True,
        "home": str(home),
        "preserved_node_id": identity.node_id,
        "preserved_revoked_node_ids": revoked_node_ids,
        "removed": removed,
        "trial_read_only_lock": True,
        "emergency_stop": False,
    }


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


def _policy_for_bundle(policy: Any) -> dict[str, Any]:
    data = runbook_catalog(policy)
    for repo in data.get("approved_repos", []):
        if "path" in repo:
            repo["path"] = "[redacted-path]"
    return data


def _reports_index(home: Path) -> list[dict[str, Any]]:
    reports_dir = home / "reports"
    if not reports_dir.exists():
        return []
    rows = []
    for path in sorted(reports_dir.glob("*"))[-50:]:
        if not path.is_file():
            continue
        item: dict[str, Any] = {"name": path.name, "size": path.stat().st_size, "modified_at": path.stat().st_mtime}
        if path.suffix.lower() == ".json":
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                item["schema"] = data.get("schema")
                item["ok"] = data.get("ok")
                item["summary"] = data.get("summary")
            except (OSError, json.JSONDecodeError):
                item["schema"] = "unreadable-json"
        rows.append(item)
    return rows


def _latest_report_summary(home: Path, *, schema: str) -> dict[str, Any] | None:
    reports_dir = home / "reports"
    if not reports_dir.exists():
        return None
    candidates = sorted(reports_dir.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True)
    for path in candidates:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if data.get("schema") == schema:
            return _sanitize_bundle(
                home,
                {
                    "name": path.name,
                    "modified_at": path.stat().st_mtime,
                    "ok": data.get("ok"),
                    "summary": data.get("summary"),
                    "runbook_results": data.get("runbook_results", []),
                },
            )
    return None


def _version_summary() -> dict[str, Any]:
    git_version = subprocess.run(["git", "--version"], check=False, capture_output=True, text=True, timeout=5) if shutil.which("git") else None
    return {
        "python_version": sys.version.split()[0],
        "platform": sys.platform,
        "git_version": None if git_version is None else (git_version.stdout or git_version.stderr).strip(),
    }


def _relay_health_payload(relay_url: str) -> dict[str, Any]:
    status, summary, detail = _relay_check(relay_url)
    return {"status": status, "summary": summary, "detail": redact_value(detail)}


def _sanitize_bundle(home: Path, value: Any) -> Any:
    home_text = str(home)
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, nested in value.items():
            key_lower = str(key).lower()
            if any(part in key_lower for part in ["token", "secret", "private", "password", "apikey", "api_key", "authorization", "invite_code"]):
                result[key] = "[redacted]"
            elif key_lower in {"safety_phrase", "phrase"}:
                result[key] = "[redacted]"
            elif key_lower in {"stdout", "stderr", "command", "output"}:
                result[key] = "[redacted-log]"
            elif key_lower.endswith("path") or key_lower in {"home", "cwd", "executable"}:
                result[key] = _redact_path(home_text, nested)
            else:
                result[key] = _sanitize_bundle(home, nested)
        return redact_value(result)
    if isinstance(value, list):
        return [_sanitize_bundle(home, item) for item in value]
    if isinstance(value, str):
        return redact_value(_redact_path(home_text, value))
    return value


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


def _bundle_markdown(bundle: dict[str, Any]) -> str:
    checks = bundle.get("preflight", {}).get("checks", [])
    check_lines = [f"- `{check.get('status')}` {check.get('name')}: {check.get('summary')}" for check in checks]
    reports = bundle.get("reports", [])
    report_lines = [f"- `{report.get('name')}` schema=`{report.get('schema')}` ok=`{report.get('ok')}`" for report in reports]
    return "\n".join(
        [
            "# GremlinChat Trial Bundle",
            "",
            f"- Created: `{bundle.get('created_at', '')}`",
            f"- Rooms: `{len(bundle.get('rooms', []))}`",
            f"- Emergency Stop: `{bundle.get('policy', {}).get('emergency_stop')}`",
            f"- Read-Only Lock: `{bundle.get('policy', {}).get('trial_read_only_lock')}`",
            "",
            "## Preflight",
            "",
            *(check_lines or ["- No preflight checks recorded."]),
            "",
            "## Reports",
            "",
            *(report_lines or ["- No reports indexed."]),
            "",
            "## JSON",
            "",
            "```json",
            json.dumps(bundle, indent=2, sort_keys=True),
            "```",
            "",
        ]
    )
