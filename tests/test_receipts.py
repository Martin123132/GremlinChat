import json
import threading
from argparse import Namespace
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from gremlinchat.cli import emergency_stop
from gremlinchat.daemon import create_daemon_http_server
from gremlinchat.receipts import create_receipt, list_receipts, verify_receipt, verify_receipt_file, write_receipt_bundle
from gremlinchat.relay import create_relay_http_server
from gremlinchat.roomops import process_room_once, request_runbook, revoke_room, sync_room_messages, verify_room
from gremlinchat.store import load_or_create_dashboard_token
from gremlinchat.trial import accept_trial_invite, create_trial_invite, listen_once, run_live_read_only_proof


def _post_json(url):
    request = Request(url, data=b"", method="POST")
    with urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def _get_json(url):
    with urlopen(url, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def _csrf_url(home, url):
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}csrf={load_or_create_dashboard_token(home)}"


def _event_types(home):
    return [receipt["event_type"] for receipt in list_receipts(home, limit=100)]


def _receipt_path(home, receipt):
    return home / "receipts" / f"{receipt['receipt_id']}.json"


def test_receipt_signing_verification_and_tamper_detection(tmp_path):
    receipt = create_receipt(
        tmp_path,
        event_type="task.requested",
        status="accepted",
        room_id="room_test",
        task_id="task_test",
        runbook="presence.ping",
        evidence={"relay_token": "secret-token", "summary": "ok"},
    )

    assert receipt["schema"] == "gremlinchat.receipt.v1"
    assert verify_receipt(receipt)["ok"] is True
    assert verify_receipt_file(_receipt_path(tmp_path, receipt))["ok"] is True

    changed_evidence = dict(receipt)
    changed_evidence["evidence"] = {**changed_evidence["evidence"], "summary": "changed"}
    assert verify_receipt(changed_evidence)["ok"] is False
    assert "evidence hash mismatch" in verify_receipt(changed_evidence)["errors"]

    changed_signature = dict(receipt)
    changed_signature["signature"] = "not-a-real-signature"
    assert verify_receipt(changed_signature)["ok"] is False
    assert "signature verification failed" in verify_receipt(changed_signature)["errors"]


def test_receipts_redact_public_unsafe_values_and_dedupe(tmp_path):
    private_repo = tmp_path / "private" / "repo"
    private_repo.mkdir(parents=True)
    first = create_receipt(
        tmp_path,
        event_type="room.verified",
        status="verified",
        room_id="room_test",
        dedupe_key="same-event",
        evidence={
            "invite_code": "GC1:private-code",
            "relay_token": "secret-token",
            "pair_secret": "secret-pair",
            "private_key": "secret-key",
            "log": "Bearer abcdefghijklmnopqrstuvwxyz123456",
            "repo_path": str(private_repo),
            "safety_phrase": "amber-brisk-cobalt-delta",
        },
    )
    second = create_receipt(
        tmp_path,
        event_type="room.verified",
        status="verified",
        room_id="room_test",
        dedupe_key="same-event",
        evidence={"repo_path": str(private_repo), "safety_phrase": "amber-brisk-cobalt-delta"},
    )
    raw = _receipt_path(tmp_path, first).read_text(encoding="utf-8")

    assert first["receipt_id"] == second["receipt_id"]
    assert len(list_receipts(tmp_path, limit=10)) == 1
    assert "GC1:private-code" not in raw
    assert "secret-token" not in raw
    assert "secret-pair" not in raw
    assert "secret-key" not in raw
    assert "Bearer " not in raw
    assert str(private_repo).replace("\\", "/") not in raw.replace("\\", "/")
    assert "amber-brisk-cobalt-delta" not in raw


def test_live_flow_creates_task_pairing_proof_and_revoke_receipts(tmp_path):
    server = create_relay_http_server(host="127.0.0.1", port=0, state_dir=tmp_path / "relay")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    alice_home = tmp_path / "alice"
    bob_home = tmp_path / "bob"
    try:
        host_packet = create_trial_invite(alice_home, relay_url=f"http://{host}:{port}")
        guest_packet = accept_trial_invite(bob_home, host_packet["invite_code"])
        alice_sync = sync_room_messages(alice_home, host_packet["room_id"])
        verify_room(alice_home, host_packet["room_id"], alice_sync["safety_phrase"])
        verify_room(bob_home, host_packet["room_id"], guest_packet["safety_phrase"])

        request = request_runbook(alice_home, host_packet["room_id"], "presence.ping", {})
        process_room_once(bob_home, host_packet["room_id"])
        sync_room_messages(alice_home, host_packet["room_id"])
        count_after_first_sync = len(list_receipts(alice_home, limit=100))
        sync_room_messages(alice_home, host_packet["room_id"])
        count_after_second_sync = len(list_receipts(alice_home, limit=100))

        proof = run_live_read_only_proof(
            alice_home,
            room_id=host_packet["room_id"],
            timeout_seconds=3,
            poll_interval=0,
            write_report=False,
            process_once=lambda: listen_once(bob_home, room_id=host_packet["room_id"]),
        )
        revoke_room(alice_home, host_packet["room_id"])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    alice_events = _event_types(alice_home)
    bob_events = _event_types(bob_home)
    assert proof["ok"] is True
    assert request["task_id"]
    assert count_after_second_sync == count_after_first_sync
    assert "room.verified" in alice_events
    assert "task.requested" in alice_events
    assert "task.result" in alice_events
    assert "trial.live_readonly_proof" in alice_events
    assert "room.revoked" in alice_events
    assert "room.verified" in bob_events
    assert "task.result" in bob_events


def test_emergency_stop_creates_receipt(tmp_path, capsys):
    emergency_stop(Namespace(home=str(tmp_path)))

    captured = capsys.readouterr().out
    events = _event_types(tmp_path)
    assert "emergency-stop" in events
    assert "receipt" in json.loads(captured)


def test_dashboard_receipt_status_and_bundle_api(tmp_path):
    create_receipt(tmp_path, event_type="room.verified", status="verified", room_id="room_test", evidence={"ok": True})
    server = create_daemon_http_server(tmp_path, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        status = _get_json(f"http://{host}:{port}/api/receipts/status")
        with pytest.raises(HTTPError) as exc_info:
            _post_json(f"http://{host}:{port}/api/receipts/bundle")
        bundle = _post_json(_csrf_url(tmp_path, f"http://{host}:{port}/api/receipts/bundle"))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert status["schema"] == "gremlinchat.receipt-status.v1"
    assert status["count"] == 1
    assert exc_info.value.code == 403
    assert bundle["ok"] is True
    assert "bundle_paths" in bundle


def test_receipt_bundle_is_verifiable_and_redacted(tmp_path):
    create_receipt(
        tmp_path,
        event_type="task.result",
        status="completed",
        room_id="room_test",
        task_id="task_test",
        runbook="gremlinchat.doctor",
        evidence={"repo_path": str(tmp_path / "private" / "repo"), "stdout": "Bearer abcdefghijklmnopqrstuvwxyz123456"},
    )
    paths = write_receipt_bundle(tmp_path, room_id="room_test")
    raw = open(paths["json"], encoding="utf-8").read()
    bundle = json.loads(raw)

    assert bundle["schema"] == "gremlinchat.receipt-bundle.v1"
    assert bundle["count"] == 1
    assert bundle["verification"][0]["ok"] is True
    assert "Bearer " not in raw
    assert str(tmp_path).replace("\\", "/") not in raw.replace("\\", "/")
