import json
import threading
from urllib.request import Request, urlopen

from gremlinchat.crypto import NodeIdentity, X25519Identity
from gremlinchat.daemon import create_daemon_http_server
from gremlinchat.store import load_policy, save_room
from gremlinchat.trial import run_trial_simulation, write_trial_report


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
