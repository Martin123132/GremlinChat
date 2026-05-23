import shutil
import subprocess
import threading

import pytest

from gremlinchat.crypto import NodeIdentity
from gremlinchat.relay import GremlinRelay, RelayClient, create_relay_http_server
from gremlinchat.runbooks import execute_runbook
from gremlinchat.store import ApprovedRepo, RunbookPolicy


def _start_relay():
    server = create_relay_http_server(host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    return server, thread, RelayClient(f"http://{host}:{port}")


def _start_relay_with_limits(**limits):
    server = create_relay_http_server(host="127.0.0.1", port=0, **limits)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    return server, thread, RelayClient(f"http://{host}:{port}")


def _stop(server, thread):
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def _envelope(sender):
    return {
        "protocol": "gremlinchat.envelope.v1",
        "room_id": "filled-by-test",
        "message_id": f"msg_{sender.node_id}",
        "created_at": 1.0,
        "sender_node_id": sender.node_id,
        "sender_public_key": sender.public_key,
        "nonce": "opaque",
        "ciphertext": "opaque-ciphertext",
        "signature": "opaque",
    }


def test_relay_locks_room_after_two_participants():
    server, thread, client = _start_relay()
    try:
        room = client.create_room(ttl_seconds=60)
        alice = NodeIdentity.generate()
        bob = NodeIdentity.generate()
        eve = NodeIdentity.generate()
        for sender in [alice, bob]:
            envelope = _envelope(sender)
            envelope["room_id"] = room["room_id"]
            assert client.post_envelope(room_id=room["room_id"], relay_token=room["relay_token"], envelope=envelope)["accepted"]
        envelope = _envelope(eve)
        envelope["room_id"] = room["room_id"]
        rejected = client.post_envelope(room_id=room["room_id"], relay_token=room["relay_token"], envelope=envelope)
        assert rejected["http_status"] == 403
        assert "locked" in rejected["error"]
    finally:
        _stop(server, thread)


def test_relay_persists_room_messages(tmp_path):
    relay = GremlinRelay(state_dir=tmp_path)
    room = relay.create_room(ttl_seconds=60)
    alice = NodeIdentity.generate()
    envelope = _envelope(alice)
    envelope["room_id"] = room.room_id
    assert relay.append_envelope(room.room_id, room.token, envelope)["accepted"]

    restored = GremlinRelay(state_dir=tmp_path)
    messages = restored.messages_after(room.room_id, room.token)
    assert messages["messages"][0]["envelope"]["sender_node_id"] == alice.node_id


def test_relay_rejects_room_message_flood():
    relay = GremlinRelay(max_messages_per_room=1)
    room = relay.create_room(ttl_seconds=60)
    alice = NodeIdentity.generate()
    first = _envelope(alice)
    first["room_id"] = room.room_id
    second = _envelope(alice)
    second["room_id"] = room.room_id

    assert relay.append_envelope(room.room_id, room.token, first)["accepted"]
    with pytest.raises(PermissionError, match="message limit"):
        relay.append_envelope(room.room_id, room.token, second)


def test_relay_rejects_oversized_request_body():
    server, thread, client = _start_relay_with_limits(max_body_bytes=8)
    try:
        rejected = client.create_room(ttl_seconds=60)
        assert rejected["http_status"] == 413
        assert "exceeds" in rejected["error"]
    finally:
        _stop(server, thread)


def test_runbooks_reject_arbitrary_commands_and_path_escape(tmp_path):
    repo_path = tmp_path / "repo"
    outside_path = tmp_path / "outside"
    repo_path.mkdir()
    outside_path.mkdir()
    policy = RunbookPolicy(approved_repos=[ApprovedRepo(name="repo", path=str(repo_path))])

    arbitrary = execute_runbook("powershell Remove-Item", {}, policy=policy, home=tmp_path)
    assert arbitrary.accepted is False
    assert "arbitrary" in arbitrary.summary

    outside = execute_runbook("repo.status", {"repo": "repo", "repo_path": str(outside_path)}, policy=policy, home=tmp_path)
    assert outside.accepted is False
    assert "escapes" in outside.summary


def test_trial_read_only_lock_blocks_enabled_write_runbook(tmp_path):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    policy = RunbookPolicy(
        approved_repos=[ApprovedRepo(name="repo", path=str(repo_path), allow_pull_ff_only=True)],
        enabled_write_runbooks=["repo.pull_ff_only"],
    )
    result = execute_runbook("repo.pull_ff_only", {"repo": "repo"}, policy=policy, home=tmp_path)
    assert result.accepted is False
    assert "read-only lock" in result.summary


@pytest.mark.skipif(shutil.which("git") is None, reason="git is required")
def test_repo_pull_blocks_dirty_tree(tmp_path):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    subprocess.run(["git", "-C", str(repo_path), "init"], check=True, capture_output=True, text=True)
    (repo_path / "work.txt").write_text("local change", encoding="utf-8")
    policy = RunbookPolicy(
        trial_read_only_lock=False,
        approved_repos=[ApprovedRepo(name="repo", path=str(repo_path), allow_pull_ff_only=True)],
        enabled_write_runbooks=["repo.pull_ff_only"],
    )
    result = execute_runbook("repo.pull_ff_only", {"repo": "repo"}, policy=policy, home=tmp_path)
    assert result.accepted is False
    assert "local changes" in result.summary
