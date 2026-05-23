import json

from gremlinchat.install import run_install_doctor, write_install_doctor_report
from gremlinchat.store import load_or_create_identity


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
