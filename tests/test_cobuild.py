import json
import threading
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import pytest

from gremlinchat.cobuild import add_project_card, cobuild_status, write_cobuild_handoff_packet
from gremlinchat.daemon import create_daemon_http_server
from gremlinchat.receipts import list_receipts
from gremlinchat.relay import create_relay_http_server
from gremlinchat.roomops import process_room_once, request_runbook, sync_room_messages, verify_room
from gremlinchat.runbooks import execute_runbook
from gremlinchat.store import load_or_create_dashboard_token, load_policy
from gremlinchat.trial import create_trial_invite, accept_trial_invite


def _post_json(url, payload=None):
    data = None
    headers = {}
    if payload is not None:
        data = urlencode(payload, doseq=True).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    request = Request(url, data=data or b"", headers=headers, method="POST")
    with urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def _get_json(url):
    with urlopen(url, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def _csrf_url(home, url):
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}csrf={load_or_create_dashboard_token(home)}"


def _sample_project(root):
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("print('hello')\n", encoding="utf-8")
    (root / ".env").write_text("API_KEY=should-not-leak\n", encoding="utf-8")
    (root / "package.json").write_text(
        json.dumps(
            {
                "name": "broken-app",
                "version": "0.1.0",
                "dependencies": {"vite": "^6.0.0"},
                "devDependencies": {"typescript": "^5.0.0"},
                "scripts": {"test": "vitest"},
            }
        ),
        encoding="utf-8",
    )
    (root / "GREMLINCHAT_ERRORS.md").write_text(
        "Build fails after launch. Bearer abcdefghijklmnopqrstuvwxyz123456\n"
        f"Local path was {root}\\private\\thing\n",
        encoding="utf-8",
    )


def test_project_bundle_uses_alias_and_redacts_local_paths(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _sample_project(project)
    add_project_card(tmp_path, alias="broken-app", path=project, description="demo")

    result = execute_runbook(
        "project.bundle",
        {"project": "broken-app", "question": "Why will this not start?"},
        policy=load_policy(tmp_path),
        home=tmp_path,
    )
    raw = json.dumps(result.to_dict(), sort_keys=True)

    assert result.accepted is True
    assert "broken-app" in raw
    assert "vite" in raw
    assert "Build fails" in raw
    assert "Bearer " not in raw
    assert str(project).replace("\\", "/") not in raw.replace("\\", "/")
    assert ".env" not in raw
    assert "[local-only]" in raw


def test_project_runbook_rejects_unknown_alias(tmp_path):
    result = execute_runbook("project.status", {"project": "missing"}, policy=load_policy(tmp_path), home=tmp_path)

    assert result.accepted is False
    assert result.status == "rejected"
    assert "not registered" in result.summary


def test_live_cobuild_request_result_receipts_and_handoff(tmp_path):
    server = create_relay_http_server(host="127.0.0.1", port=0, state_dir=tmp_path / "relay")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    alice_home = tmp_path / "alice"
    bob_home = tmp_path / "bob"
    project = tmp_path / "bob-project"
    project.mkdir()
    _sample_project(project)
    try:
        host_packet = create_trial_invite(alice_home, relay_url=f"http://{host}:{port}")
        guest_packet = accept_trial_invite(bob_home, host_packet["invite_code"])
        alice_sync = sync_room_messages(alice_home, host_packet["room_id"])
        verify_room(alice_home, host_packet["room_id"], alice_sync["safety_phrase"])
        verify_room(bob_home, host_packet["room_id"], guest_packet["safety_phrase"])
        add_project_card(bob_home, alias="glyns-broken-app", path=project)

        request = request_runbook(
            alice_home,
            host_packet["room_id"],
            "project.bundle",
            {"project": "glyns-broken-app", "question": "Find the startup blocker."},
        )
        processed = process_room_once(bob_home, host_packet["room_id"])
        synced = sync_room_messages(alice_home, host_packet["room_id"])
        result_messages = [message for message in synced["decrypted_messages"] if message.get("task_id") == request["task_id"]]
        handoff = write_cobuild_handoff_packet(alice_home, room_id=host_packet["room_id"], task_id=request["task_id"])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    handoff_raw = open(handoff["markdown"], encoding="utf-8").read()
    alice_receipts = list_receipts(alice_home, limit=50)
    bob_receipts = list_receipts(bob_home, limit=50)

    assert processed["count"] == 1
    assert result_messages[-1]["result"]["accepted"] is True
    assert "Use the attached redacted evidence" in handoff_raw
    assert str(project).replace("\\", "/") not in handoff_raw.replace("\\", "/")
    assert any(receipt["event_type"] == "cobuild.task.requested" for receipt in alice_receipts)
    assert any(receipt["event_type"] == "cobuild.task.result" for receipt in alice_receipts)
    assert any(receipt["event_type"] == "cobuild.task.result" for receipt in bob_receipts)


def test_dashboard_cobuild_apis_require_csrf_and_create_project(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    _sample_project(project)
    server = create_daemon_http_server(tmp_path, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        with pytest.raises(HTTPError) as exc_info:
            _post_json(f"http://{host}:{port}/api/cobuild/project/add", {"alias": "local-app", "path": str(project)})
        created = _post_json(
            _csrf_url(tmp_path, f"http://{host}:{port}/api/cobuild/project/add"),
            {"alias": "local-app", "path": str(project), "description": "dashboard add"},
        )
        status = _get_json(f"http://{host}:{port}/api/cobuild/status")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert exc_info.value.code == 403
    assert created["ok"] is True
    assert status["schema"] == "gremlinchat.cobuild-status.v1"
    assert status["projects"][0]["alias"] == "local-app"
    assert cobuild_status(tmp_path)["project_count"] == 1
