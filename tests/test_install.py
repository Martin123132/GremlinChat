import json
import threading
from argparse import Namespace

from gremlinchat.cli import open_daemon
from gremlinchat.daemon import create_daemon_http_server
from gremlinchat.install import run_install_doctor, write_install_doctor_report
from gremlinchat.store import default_home, load_or_create_identity


def test_default_home_honors_gremlinchat_home(monkeypatch, tmp_path):
    configured = tmp_path / "state"
    monkeypatch.setenv("GREMLINCHAT_HOME", str(configured))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))

    assert default_home() == configured


def test_install_doctor_creates_local_state_without_hard_failures(tmp_path):
    report = run_install_doctor(tmp_path)
    checks = {check["name"]: check for check in report["checks"]}

    assert report["schema"] == "gremlinchat.install-doctor.v1"
    assert report["ok"] is True
    assert checks["python"]["status"] == "pass"
    assert checks["identity"]["status"] == "pass"
    assert checks["dashboard_token"]["status"] == "pass"
    assert checks["reports_writable"]["status"] == "pass"
    assert checks["read_only_lock"]["status"] == "pass"
    assert checks["emergency_stop"]["status"] == "pass"
    assert checks.get("windows_venv", {"status": "warning"})["status"] in {"pass", "warning"}
    assert load_or_create_identity(tmp_path).node_id


def test_install_doctor_report_is_redacted(tmp_path):
    report = run_install_doctor(tmp_path)
    report["invite_code"] = "GC1:very-private"
    report["private_key"] = "do-not-share"
    paths = write_install_doctor_report(tmp_path, report)
    raw = open(paths["json"], encoding="utf-8").read()
    parsed = json.loads(raw)

    assert parsed["schema"] == "gremlinchat.install-doctor.v1"
    assert "GC1:very-private" not in raw
    assert "do-not-share" not in raw


def test_install_doctor_warns_when_home_is_under_localappdata(monkeypatch, tmp_path):
    localappdata = tmp_path / "localappdata"
    home = localappdata / "GremlinChat"
    monkeypatch.setenv("LOCALAPPDATA", str(localappdata))

    report = run_install_doctor(home)
    checks = {check["name"]: check for check in report["checks"]}

    assert report["ok"] is True
    assert checks["home_storage_posture"]["status"] == "warning"
    assert "under_localappdata" in checks["home_storage_posture"]["detail"]["flags"]
    assert checks["artifact_storage_posture"]["status"] == "warning"


def test_daemon_open_reports_existing_dashboard_without_browser(tmp_path, capsys):
    server = create_daemon_http_server(tmp_path, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        open_daemon(Namespace(home=str(tmp_path), host=host, port=port, wait_seconds=1.0, no_browser=True))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is True
    assert result["started"] is False
    assert result["browser_opened"] is False
    assert result["url"] == f"http://{host}:{port}/dashboard"
