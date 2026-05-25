import json
import threading
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

import pytest

from gremlinchat.daemon import create_daemon_http_server
from gremlinchat.pairing import pair_host, pair_join, pair_status, pair_verify
from gremlinchat.receipts import list_receipts
from gremlinchat.relay import create_relay_http_server
from gremlinchat.roomops import GremlinChatError, request_runbook, sync_room_messages
from gremlinchat.store import load_or_create_dashboard_token, load_rooms


def _post_json(url, data=b""):
    request = Request(url, data=data, method="POST")
    with urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def _get_json(url):
    with urlopen(url, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def _csrf_url(home, url):
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}csrf={load_or_create_dashboard_token(home)}"


def _start_relay(tmp_path):
    server = create_relay_http_server(host="127.0.0.1", port=0, state_dir=tmp_path / "relay")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    return server, thread, f"http://{host}:{port}"


def _stop(server, thread):
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def _events(home):
    return {receipt["event_type"] for receipt in list_receipts(home, limit=100)}


def test_pairing_ceremony_hosts_joins_verifies_and_rejects_third_peer(tmp_path):
    server, thread, relay_url = _start_relay(tmp_path)
    alice_home = tmp_path / "alice"
    bob_home = tmp_path / "bob"
    eve_home = tmp_path / "eve"
    try:
        host_packet = pair_host(alice_home, relay_url=relay_url)
        assert host_packet["invite_code"].startswith("GC1:")
        assert host_packet["host_hello_posted"] is True
        assert pair_status(alice_home)["rooms"][0]["pairing_state"] == "waiting_for_guest"

        guest_packet = pair_join(bob_home, host_packet["invite_code"])
        assert guest_packet["hello_posted"] is True
        with pytest.raises(GremlinChatError, match="rejected|locked"):
            pair_join(eve_home, host_packet["invite_code"])
        assert load_rooms(eve_home) == []

        with pytest.raises(GremlinChatError, match="not verified"):
            request_runbook(alice_home, host_packet["room_id"], "presence.ping", {})

        host_sync = sync_room_messages(alice_home, host_packet["room_id"])
        assert host_sync["safety_phrase"] == guest_packet["safety_phrase"]
        pair_verify(alice_home, room_id=host_packet["room_id"], phrase=host_sync["safety_phrase"])
        pair_verify(bob_home, room_id=host_packet["room_id"], phrase=guest_packet["safety_phrase"])
    finally:
        _stop(server, thread)

    assert pair_status(alice_home)["rooms"][0]["pairing_state"] == "verified"
    assert {"pairing.invite_created", "pairing.peer_joined", "room.verified", "pairing.room_enabled"} <= _events(alice_home)
    assert {"pairing.invite_accepted", "room.verified", "pairing.room_enabled"} <= _events(bob_home)


def test_pair_status_does_not_show_invite_unless_requested(tmp_path):
    server, thread, relay_url = _start_relay(tmp_path)
    try:
        host_packet = pair_host(tmp_path / "alice", relay_url=relay_url)
        hidden = pair_status(tmp_path / "alice")
        shown = pair_status(tmp_path / "alice", include_invite=True)
    finally:
        _stop(server, thread)

    assert hidden["latest_invite"]["invite_available"] is True
    assert "invite_code" not in hidden["latest_invite"]
    assert shown["latest_invite"]["invite_code"] == host_packet["invite_code"]


def test_dashboard_pairing_api_creates_invite_without_public_status_leak(tmp_path):
    relay_server, relay_thread, relay_url = _start_relay(tmp_path)
    daemon_home = tmp_path / "dashboard"
    daemon = create_daemon_http_server(daemon_home, host="127.0.0.1", port=0)
    daemon_thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    daemon_thread.start()
    host, port = daemon.server_address
    try:
        with pytest.raises(HTTPError) as exc_info:
            _post_json(f"http://{host}:{port}/api/pair/host?relay={quote(relay_url, safe='')}")
        created = _post_json(_csrf_url(daemon_home, f"http://{host}:{port}/api/pair/host?relay={quote(relay_url, safe='')}"))
        status = _get_json(f"http://{host}:{port}/api/pair/status")
    finally:
        daemon.shutdown()
        daemon.server_close()
        daemon_thread.join(timeout=2)
        _stop(relay_server, relay_thread)

    assert exc_info.value.code == 403
    assert created["ok"] is True
    assert created["pairing"]["invite_code"].startswith("GC1:")
    assert status["schema"] == "gremlinchat.pair-status.v1"
    assert status["latest_invite"]["invite_available"] is True
    assert "invite_code" not in status["latest_invite"]
