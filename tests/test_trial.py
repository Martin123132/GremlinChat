import json
import threading
from urllib.request import Request, urlopen

from gremlinchat.crypto import NodeIdentity, X25519Identity
from gremlinchat.daemon import create_daemon_http_server
from gremlinchat.relay import create_relay_http_server
from gremlinchat.roomops import sync_room_messages, verify_room
from gremlinchat.store import load_policy, save_policy, save_room
from gremlinchat.trial import accept_trial_invite, create_trial_invite, enforce_trial_read_only_lock, listen_once, run_live_read_only_proof, run_trial_simulation, write_trial_report


def _post_json(url):
    request = Request(url, data=b"", method="POST")
    with urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


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
        revoke = _post_json(f"http://{host}:{port}/api/rooms/revoke?room_id=room_dashboard")
        stop = _post_json(f"http://{host}:{port}/api/emergency-stop")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    policy = load_policy(tmp_path)
    assert revoke["ok"] is True
    assert stop["ok"] is True
    assert peer.node_id in policy.revoked_node_ids
    assert policy.emergency_stop is True
