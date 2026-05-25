import json
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from gremlinchat.crypto import NodeIdentity, X25519Identity
from gremlinchat.daemon import create_daemon_http_server
from gremlinchat.relay import create_relay_http_server
from gremlinchat.roomops import sync_room_messages, verify_room
from gremlinchat.store import ApprovedRepo, load_approvals, load_or_create_dashboard_token, load_or_create_identity, load_policy, load_rooms, save_approvals, save_policy, save_room
from gremlinchat.trial import (
    RESET_CONFIRMATION,
    accept_trial_invite,
    build_trial_checklist,
    create_trial_invite,
    enforce_trial_read_only_lock,
    listen_once,
    reset_local_trial,
    run_guest_session,
    run_host_session,
    run_live_read_only_proof,
    run_trial_simulation,
    write_trial_bundle,
    write_trial_report,
)


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


def _trial_room(peer=None, peer_x=None, *, verified=False, disabled=False):
    peer = NodeIdentity.generate() if peer is None else peer
    peer_x = X25519Identity.generate() if peer_x is None else peer_x
    return {
        "room_id": "room_trial",
        "relay_url": "http://127.0.0.1:9",
        "relay_token": "test-token",
        "pair_secret": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "peer_node_id": peer.node_id,
        "peer_public_key": peer.public_key,
        "peer_x25519_public_key": peer_x.public_key,
        "safety_phrase": "amber-brisk-cobalt-delta",
        "verified": verified,
        "disabled": disabled,
        "processed_message_ids": [],
    }


def test_trial_simulation_completes_read_only_flow():
    report = run_trial_simulation(write_report_home=None)

    assert report["ok"] is True
    assert report["blocked_after_revoke"] is True
    assert report["relay_state_persisted"] is True
    assert {item["runbook"] for item in report["runbook_results"]} == {"presence.ping", "machine.status", "gremlinchat.doctor"}
    assert all(item["result_accepted"] for item in report["runbook_results"])


def test_trial_report_redacts_public_unsafe_values(tmp_path):
    paths = write_trial_report(
        tmp_path,
        {
            "ok": True,
            "summary": "redaction proof",
            "relay_token": "secret-token",
            "log": "Bearer abcdefghijklmnopqrstuvwxyz123456",
        },
    )

    assert "secret-token" not in open(paths["json"], encoding="utf-8").read()
    assert "Bearer " not in open(paths["markdown"], encoding="utf-8").read()


def test_live_trial_host_guest_and_proof(tmp_path):
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

        proof = run_live_read_only_proof(
            alice_home,
            room_id=host_packet["room_id"],
            timeout_seconds=3,
            poll_interval=0,
            write_report=False,
            process_once=lambda: listen_once(bob_home, room_id=host_packet["room_id"]),
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert proof["ok"] is True
    assert {item["runbook"] for item in proof["runbook_results"]} == {"presence.ping", "machine.status", "gremlinchat.doctor"}
    assert all(item["result_accepted"] for item in proof["runbook_results"])


def test_trial_listener_enforces_read_only_lock(tmp_path):
    policy = load_policy(tmp_path)
    policy.trial_read_only_lock = False
    save_policy(policy, tmp_path)

    result = enforce_trial_read_only_lock(tmp_path)
    updated = load_policy(tmp_path)

    assert result == {"trial_read_only_lock": True, "changed": True}
    assert updated.trial_read_only_lock is True


def test_trial_checklist_tracks_role_and_room_states(tmp_path):
    host_empty = build_trial_checklist(tmp_path, role="host", relay_url="http://relay.local:8778")
    guest_empty = build_trial_checklist(tmp_path, role="guest")
    assert "gremlinchat trial host-session --relay http://relay.local:8778" in host_empty["commands"]
    assert "gremlinchat trial guest-session GC1:..." in guest_empty["commands"]

    peer = NodeIdentity.generate()
    save_room(_trial_room(peer=peer, verified=False), tmp_path)
    guest_joined = build_trial_checklist(tmp_path, role="guest")
    assert any(command.startswith("gremlinchat pair verify --phrase") for command in guest_joined["commands"])

    room = load_rooms(tmp_path)[0]
    room["verified"] = True
    save_room(room, tmp_path)
    host_verified = build_trial_checklist(tmp_path, role="host")
    guest_verified = build_trial_checklist(tmp_path, role="guest")
    assert "gremlinchat trial prove" in host_verified["commands"]
    assert "gremlinchat trial listen" in guest_verified["commands"]

    policy = load_policy(tmp_path)
    policy.emergency_stop = True
    policy.revoked_node_ids.append(peer.node_id)
    save_policy(policy, tmp_path)
    flagged = build_trial_checklist(tmp_path, role="host")
    assert flagged["revoked_room_count"] == 1
    assert flagged["emergency_stop"] is True
    assert flagged["warnings"]


def test_trial_bundle_redacts_sensitive_values_and_indexes_sections(tmp_path):
    private_repo = tmp_path / "private" / "repo"
    private_repo.mkdir(parents=True)
    policy = load_policy(tmp_path)
    policy.approved_repos = [ApprovedRepo("private", str(private_repo), allow_pull_ff_only=True)]
    save_policy(policy, tmp_path)
    save_room(_trial_room(verified=True), tmp_path)
    write_trial_report(
        tmp_path,
        {
            "schema": "gremlinchat.live-readonly-proof.v1",
            "ok": True,
            "summary": "contains secrets",
            "relay_token": "secret-token",
            "stdout": "Bearer abcdefghijklmnopqrstuvwxyz123456",
            "repo_path": str(private_repo),
        },
    )

    paths = write_trial_bundle(tmp_path)
    raw = open(paths["json"], encoding="utf-8").read()
    bundle = json.loads(raw)

    assert bundle["schema"] == "gremlinchat.trial-bundle.v1"
    assert {"preflight", "rooms", "policy", "audit", "reports", "versions"} <= set(bundle)
    assert "secret-token" not in raw
    assert "Bearer " not in raw
    assert str(private_repo).replace("\\", "/") not in raw.replace("\\", "/")
    assert "amber-brisk-cobalt-delta" not in raw
    assert bundle["policy"]["approved_repos"][0]["path"] == "[redacted-path]"


def test_trial_reset_preserves_identity_and_revoked_peers(tmp_path):
    identity = load_or_create_identity(tmp_path)
    peer = NodeIdentity.generate()
    save_room(_trial_room(peer=peer, verified=True), tmp_path)
    save_approvals(tmp_path, [{"approval_id": "approval_test", "status": "pending"}])
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    (reports_dir / "trial-test.json").write_text("{}", encoding="utf-8")
    policy = load_policy(tmp_path)
    policy.emergency_stop = True
    policy.revoked_node_ids.append(peer.node_id)
    save_policy(policy, tmp_path)

    result = reset_local_trial(tmp_path, confirm=RESET_CONFIRMATION)

    assert result["preserved_node_id"] == identity.node_id
    assert load_or_create_identity(tmp_path).node_id == identity.node_id
    assert load_rooms(tmp_path) == []
    assert load_approvals(tmp_path) == []
    assert not reports_dir.exists()
    reset_policy = load_policy(tmp_path)
    assert reset_policy.emergency_stop is False
    assert reset_policy.trial_read_only_lock is True
    assert reset_policy.revoked_node_ids == [peer.node_id]


def test_trial_host_session_creates_one_invite_and_enforces_read_only_lock(tmp_path):
    server = create_relay_http_server(host="127.0.0.1", port=0, state_dir=tmp_path / "relay")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    alice_home = tmp_path / "alice"
    policy = load_policy(alice_home)
    policy.trial_read_only_lock = False
    save_policy(policy, alice_home)
    try:
        first = run_host_session(alice_home, relay_url=f"http://{host}:{port}")
        second = run_host_session(alice_home, relay_url=f"http://{host}:{port}")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert first["ok"] is True
    assert first["created_invite"] is True
    assert first["read_only_lock"] == {"trial_read_only_lock": True, "changed": True}
    assert first["invite_packet"]["invite_code"].startswith("GC1:")
    assert second["ok"] is True
    assert second["created_invite"] is False
    assert second["invite_packet"] is None
    assert len(load_rooms(alice_home)) == 1
    assert load_policy(alice_home).trial_read_only_lock is True


def test_trial_guest_session_joins_once_and_enforces_read_only_lock(tmp_path):
    server = create_relay_http_server(host="127.0.0.1", port=0, state_dir=tmp_path / "relay")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    alice_home = tmp_path / "alice"
    bob_home = tmp_path / "bob"
    policy = load_policy(bob_home)
    policy.trial_read_only_lock = False
    save_policy(policy, bob_home)
    try:
        host_packet = create_trial_invite(alice_home, relay_url=f"http://{host}:{port}")
        first = run_guest_session(bob_home, host_packet["invite_code"])
        second = run_guest_session(bob_home, host_packet["invite_code"])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert first["ok"] is True
    assert first["joined"] is True
    assert first["read_only_lock"] == {"trial_read_only_lock": True, "changed": True}
    assert first["join_packet"]["hello_posted"] is True
    assert second["ok"] is True
    assert second["joined"] is False
    assert second["join_packet"] is None
    assert len(load_rooms(bob_home)) == 1
    assert load_policy(bob_home).trial_read_only_lock is True


def test_dashboard_revoke_and_emergency_stop_posts(tmp_path):
    peer = NodeIdentity.generate()
    peer_x = X25519Identity.generate()
    save_room(
        {
            "room_id": "room_dashboard",
            "relay_url": "http://127.0.0.1:9",
            "relay_token": "test-token",
            "pair_secret": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "peer_node_id": peer.node_id,
            "peer_public_key": peer.public_key,
            "peer_x25519_public_key": peer_x.public_key,
            "safety_phrase": "amber-brisk-cobalt-delta",
            "verified": True,
            "disabled": False,
            "processed_message_ids": [],
        },
        tmp_path,
    )
    server = create_daemon_http_server(tmp_path, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        with pytest.raises(HTTPError) as exc_info:
            _post_json(f"http://{host}:{port}/api/emergency-stop")
        revoke = _post_json(_csrf_url(tmp_path, f"http://{host}:{port}/api/rooms/revoke?room_id=room_dashboard"))
        stop = _post_json(_csrf_url(tmp_path, f"http://{host}:{port}/api/emergency-stop"))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    policy = load_policy(tmp_path)
    assert exc_info.value.code == 403
    assert revoke["ok"] is True
    assert stop["ok"] is True
    assert peer.node_id in policy.revoked_node_ids
    assert policy.emergency_stop is True


def test_dashboard_trial_status_bundle_and_reset_apis(tmp_path):
    identity = load_or_create_identity(tmp_path)
    save_room(_trial_room(verified=True), tmp_path)
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    (reports_dir / "trial-test.json").write_text("{}", encoding="utf-8")
    server = create_daemon_http_server(tmp_path, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        public_status = _get_json(f"http://{host}:{port}/api/status")
        status = _get_json(f"http://{host}:{port}/api/trial/status")
        bundle = _post_json(_csrf_url(tmp_path, f"http://{host}:{port}/api/trial/bundle"))
        reset = _post_json(_csrf_url(tmp_path, f"http://{host}:{port}/api/trial/reset-local?confirm={RESET_CONFIRMATION}"))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert "csrf_token" not in public_status
    assert status["schema"] == "gremlinchat.trial-status.v1"
    assert bundle["ok"] is True
    assert "bundle_paths" in bundle
    assert reset["ok"] is True
    assert load_or_create_identity(tmp_path).node_id == identity.node_id
    assert load_rooms(tmp_path) == []
