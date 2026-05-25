"""GremlinChat command line interface."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from .daemon import create_daemon_http_server
from .install import run_install_doctor, write_install_doctor_report
from .pairing import pair_host, pair_join, pair_status, pair_verify
from .receipts import (
    compare_receipts,
    create_receipt,
    find_receipt,
    import_partner_receipts,
    list_receipts,
    list_partner_receipts,
    receipt_summary,
    verify_receipt_bundle_file,
    verify_receipt_file,
    write_receipt_bundle,
)
from .relay import create_relay_http_server
from .roomops import (
    GremlinChatError,
    disable_room as disable_room_state,
    fetch_room_messages as fetch_room_messages_state,
    load_room as load_room_state,
    owner_rejected_result as owner_rejected_result_state,
    process_room_once as room_process_once,
    request_runbook as send_runbook_request,
    require_room_verified as require_room_verified_state,
    revoke_room as revoke_room_state,
    room_key as room_key_state,
    sync_room_messages,
    verify_room as verify_room_state,
)
from .runbooks import execute_runbook, runbook_catalog, runbook_result_json
from .store import (
    ApprovedRepo,
    decide_approval,
    default_home,
    ensure_home,
    load_approvals,
    load_or_create_identity,
    load_or_create_x25519_identity,
    load_policy,
    save_policy,
)
from .trial import (
    RESET_CONFIRMATION,
    accept_trial_invite,
    build_trial_checklist,
    create_trial_invite,
    current_trial_snapshot,
    listen_once,
    reset_local_trial,
    run_guest_session,
    run_host_session,
    run_live_read_only_proof,
    run_preflight,
    run_trial_simulation,
    write_trial_bundle,
    write_trial_report,
)


def _home(raw: str | None) -> Path:
    return ensure_home(default_home() if raw is None else Path(raw))


def setup(args: argparse.Namespace) -> None:
    home = _home(args.home)
    identity = load_or_create_identity(home)
    x25519_identity = load_or_create_x25519_identity(home)
    print(json.dumps({"configured": True, "home": str(home), "node_id": identity.node_id, "public_key": identity.public_key, "x25519_public_key": x25519_identity.public_key, "policy": runbook_catalog(load_policy(home))}, indent=2, sort_keys=True))


def serve_relay(args: argparse.Namespace) -> None:
    if args.host == "0.0.0.0":
        print("WARNING: relay is bound to 0.0.0.0. Use a specific LAN/Tailscale IP for private trials when possible.")
    server = create_relay_http_server(
        host=args.host,
        port=args.port,
        state_dir=args.state_dir,
        max_body_bytes=args.max_body_bytes,
        max_messages_per_room=args.max_messages_per_room,
        max_envelope_bytes=args.max_envelope_bytes,
    )
    print(f"GremlinChat relay listening: http://{args.host}:{args.port}")
    if args.state_dir:
        print(f"GremlinChat relay persistence: {Path(args.state_dir).expanduser().resolve()}")
    print(f"GremlinChat relay limits: max_body_bytes={args.max_body_bytes} max_envelope_bytes={args.max_envelope_bytes} max_messages_per_room={args.max_messages_per_room}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("shutting down GremlinChat relay")
    finally:
        server.server_close()


def serve_daemon(args: argparse.Namespace) -> None:
    home = _home(args.home)
    load_or_create_identity(home)
    server = create_daemon_http_server(home, host=args.host, port=args.port)
    print(f"GremlinChat dashboard: http://{args.host}:{args.port}/dashboard")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("shutting down GremlinChat dashboard")
    finally:
        server.server_close()


def create_room(args: argparse.Namespace) -> None:
    try:
        result = pair_host(_home(args.home), relay_url=args.relay, ttl_seconds=args.ttl_seconds, read_only_lock=False)
    except GremlinChatError as exc:
        raise SystemExit(str(exc)) from exc
    result["note"] = "Share privately. Do not commit invite codes. Run room sync, compare the safety phrase by phone/email, then run pair verify."
    print(json.dumps(result, indent=2, sort_keys=True))


def join_room(args: argparse.Namespace) -> None:
    try:
        result = pair_join(_home(args.home), args.code, read_only_lock=False)
    except (GremlinChatError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    result["next_step"] = "Compare this safety phrase with the other person, then run pair verify locally."
    print(json.dumps(result, indent=2, sort_keys=True))


def pair_host_command(args: argparse.Namespace) -> None:
    try:
        print(json.dumps(pair_host(_home(args.home), relay_url=args.relay, ttl_seconds=args.ttl_seconds), indent=2, sort_keys=True))
    except GremlinChatError as exc:
        raise SystemExit(str(exc)) from exc


def pair_join_command(args: argparse.Namespace) -> None:
    try:
        print(json.dumps(pair_join(_home(args.home), args.code), indent=2, sort_keys=True))
    except (GremlinChatError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc


def pair_verify_command(args: argparse.Namespace) -> None:
    try:
        print(json.dumps(pair_verify(_home(args.home), room_id=args.room_id, phrase=args.phrase), indent=2, sort_keys=True))
    except GremlinChatError as exc:
        raise SystemExit(str(exc)) from exc


def pair_status_command(args: argparse.Namespace) -> None:
    print(json.dumps(pair_status(_home(args.home), include_invite=args.show_invite), indent=2, sort_keys=True))


def sync_room(args: argparse.Namespace) -> None:
    try:
        print(json.dumps(sync_room_messages(_home(args.home), args.room_id), indent=2, sort_keys=True))
    except GremlinChatError as exc:
        raise SystemExit(str(exc)) from exc


def verify_room(args: argparse.Namespace) -> None:
    try:
        print(json.dumps(verify_room_state(_home(args.home), args.room_id, args.phrase), indent=2, sort_keys=True))
    except GremlinChatError as exc:
        raise SystemExit(str(exc)) from exc


def disable_room(args: argparse.Namespace) -> None:
    try:
        print(json.dumps(disable_room_state(_home(args.home), args.room_id), indent=2, sort_keys=True))
    except GremlinChatError as exc:
        raise SystemExit(str(exc)) from exc


def revoke_room(args: argparse.Namespace) -> None:
    try:
        print(json.dumps(revoke_room_state(_home(args.home), args.room_id), indent=2, sort_keys=True))
    except GremlinChatError as exc:
        raise SystemExit(str(exc)) from exc


def request_runbook(args: argparse.Namespace) -> None:
    try:
        print(json.dumps(send_runbook_request(_home(args.home), args.room_id, args.runbook, json.loads(args.payload_json or "{}")), indent=2, sort_keys=True))
    except (GremlinChatError, json.JSONDecodeError) as exc:
        raise SystemExit(str(exc)) from exc


def process_room(args: argparse.Namespace) -> None:
    print(json.dumps(_process_room_once(_home(args.home), args.room_id), indent=2, sort_keys=True))


def loop_room(args: argparse.Namespace) -> None:
    home = _home(args.home)
    iteration = 0
    try:
        while args.max_iterations is None or iteration < args.max_iterations:
            summary = _process_room_once(home, args.room_id)
            print(json.dumps({"iteration": iteration, **summary}, sort_keys=True))
            iteration += 1
            if args.stop_when_idle and summary["count"] == 0:
                return
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("stopping GremlinChat room loop")


def _process_room_once(home: Path, room_id: str | None) -> dict:
    try:
        return room_process_once(home, room_id)
    except GremlinChatError as exc:
        raise SystemExit(str(exc)) from exc


def show_status(args: argparse.Namespace) -> None:
    home = _home(args.home)
    identity = load_or_create_identity(home)
    print(json.dumps({"home": str(home), "node_id": identity.node_id, "policy": runbook_catalog(load_policy(home))}, indent=2, sort_keys=True))


def list_runbooks(args: argparse.Namespace) -> None:
    print(json.dumps(runbook_catalog(load_policy(_home(args.home))), indent=2, sort_keys=True))


def run_runbook(args: argparse.Namespace) -> None:
    home = _home(args.home)
    result = execute_runbook(args.name, json.loads(args.payload_json or "{}"), policy=load_policy(home), home=home, requester_node_id=args.requester_node_id)
    print(runbook_result_json(result))
    if not result.accepted:
        raise SystemExit(1)


def emergency_stop(args: argparse.Namespace) -> None:
    home = _home(args.home)
    policy = load_policy(home)
    policy.emergency_stop = True
    save_policy(policy, home)
    receipt = create_receipt(
        home,
        event_type="emergency-stop",
        status="active",
        evidence={"emergency_stop": True, "trigger": "cli", "event_at": round(time.time(), 3)},
    )
    print(json.dumps({"emergency_stop": True, "home": str(home), "receipt": receipt_summary(receipt)}, indent=2, sort_keys=True))


def install_doctor_command(args: argparse.Namespace) -> None:
    home = _home(args.home)
    report = run_install_doctor(home)
    if args.write_report:
        report["report_paths"] = write_install_doctor_report(home, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    if not report["ok"]:
        raise SystemExit(1)


def receipt_list_command(args: argparse.Namespace) -> None:
    home = _home(args.home)
    receipts = list_partner_receipts(home, limit=args.limit) if args.partner else list_receipts(home, limit=args.limit)
    print(json.dumps({"schema": "gremlinchat.receipt-list.v1", "source": "partner" if args.partner else "local", "receipts": [receipt_summary(item) for item in receipts]}, indent=2, sort_keys=True))


def receipt_show_command(args: argparse.Namespace) -> None:
    try:
        print(json.dumps(find_receipt(_home(args.home), args.receipt), indent=2, sort_keys=True))
    except (FileNotFoundError, OSError, json.JSONDecodeError) as exc:
        raise SystemExit(str(exc)) from exc


def receipt_verify_command(args: argparse.Namespace) -> None:
    try:
        verification = verify_receipt_file(args.path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(verification, indent=2, sort_keys=True))
    if not verification["ok"]:
        raise SystemExit(1)


def receipt_verify_bundle_command(args: argparse.Namespace) -> None:
    try:
        verification = verify_receipt_bundle_file(args.path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(verification, indent=2, sort_keys=True))
    if not verification["ok"]:
        raise SystemExit(1)


def receipt_import_command(args: argparse.Namespace) -> None:
    try:
        result = import_partner_receipts(_home(args.home), args.path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(result, indent=2, sort_keys=True))
    if not result["ok"]:
        raise SystemExit(1)


def receipt_compare_command(args: argparse.Namespace) -> None:
    result = compare_receipts(_home(args.home), room_id=args.room_id)
    print(json.dumps(result, indent=2, sort_keys=True))
    if not result["ok"] and args.strict:
        raise SystemExit(1)


def receipt_bundle_command(args: argparse.Namespace) -> None:
    print(json.dumps({"bundle_paths": write_receipt_bundle(_home(args.home), room_id=args.room_id)}, indent=2, sort_keys=True))


def approve_repo(args: argparse.Namespace) -> None:
    home = _home(args.home)
    policy = load_policy(home)
    repo = ApprovedRepo(args.name, str(Path(args.path).expanduser().resolve()), allow_pull_ff_only=args.allow_pull, allow_tests=list(args.allow_test))
    policy.approved_repos = [existing for existing in policy.approved_repos if existing.name != repo.name]
    policy.approved_repos.append(repo)
    if args.allow_pull and "repo.pull_ff_only" not in policy.enabled_write_runbooks:
        policy.enabled_write_runbooks.append("repo.pull_ff_only")
    save_policy(policy, home)
    print(json.dumps({"approved_repo": repo.to_dict(), "home": str(home)}, indent=2, sort_keys=True))


def list_approvals_command(args: argparse.Namespace) -> None:
    print(json.dumps({"approvals": load_approvals(_home(args.home))}, indent=2, sort_keys=True))


def decide_approval_command(args: argparse.Namespace) -> None:
    home = _home(args.home)
    approval = decide_approval(home, args.approval_id, approved=args.approval_command == "approve")
    print(json.dumps({"approval": approval}, indent=2, sort_keys=True))


def trial_preflight_command(args: argparse.Namespace) -> None:
    report = run_preflight(_home(args.home), relay_url=args.relay, dashboard_port=args.dashboard_port, relay_port=args.relay_port)
    if args.write_report:
        report["report_paths"] = write_trial_report(_home(args.home), report)
    print(json.dumps(report, indent=2, sort_keys=True))
    if not report["ok"]:
        raise SystemExit(1)


def trial_host_command(args: argparse.Namespace) -> None:
    try:
        print(json.dumps(create_trial_invite(_home(args.home), relay_url=args.relay, ttl_seconds=args.ttl_seconds), indent=2, sort_keys=True))
    except GremlinChatError as exc:
        raise SystemExit(str(exc)) from exc


def trial_guest_command(args: argparse.Namespace) -> None:
    try:
        print(json.dumps(accept_trial_invite(_home(args.home), args.code), indent=2, sort_keys=True))
    except (GremlinChatError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc


def trial_host_session_command(args: argparse.Namespace) -> None:
    try:
        report = run_host_session(_home(args.home), relay_url=args.relay, ttl_seconds=args.ttl_seconds)
    except GremlinChatError as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(report, indent=2, sort_keys=True))
    if not report["ok"]:
        raise SystemExit(1)


def trial_guest_session_command(args: argparse.Namespace) -> None:
    try:
        report = run_guest_session(_home(args.home), args.code)
    except (GremlinChatError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(report, indent=2, sort_keys=True))
    if not report["ok"]:
        raise SystemExit(1)


def trial_prove_command(args: argparse.Namespace) -> None:
    try:
        report = run_live_read_only_proof(
            _home(args.home),
            room_id=args.room_id,
            timeout_seconds=args.timeout_seconds,
            poll_interval=args.interval,
            write_report=not args.no_report,
        )
    except GremlinChatError as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(report, indent=2, sort_keys=True))
    if not report["ok"]:
        raise SystemExit(1)


def trial_listen_command(args: argparse.Namespace) -> None:
    home = _home(args.home)
    iteration = 0
    try:
        while args.max_iterations is None or iteration < args.max_iterations:
            try:
                summary = listen_once(home, room_id=args.room_id)
            except GremlinChatError as exc:
                raise SystemExit(str(exc)) from exc
            print(json.dumps({"iteration": iteration, **summary}, sort_keys=True))
            iteration += 1
            if args.stop_when_idle and summary["count"] == 0:
                return
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("stopping GremlinChat trial listener")


def trial_checklist_command(args: argparse.Namespace) -> None:
    try:
        print(json.dumps(build_trial_checklist(_home(args.home), role=args.role, relay_url=args.relay), indent=2, sort_keys=True))
    except GremlinChatError as exc:
        raise SystemExit(str(exc)) from exc


def trial_bundle_command(args: argparse.Namespace) -> None:
    paths = write_trial_bundle(_home(args.home), relay_url=args.relay)
    print(json.dumps({"bundle_paths": paths}, indent=2, sort_keys=True))


def trial_reset_local_command(args: argparse.Namespace) -> None:
    try:
        print(json.dumps(reset_local_trial(_home(args.home), confirm=args.confirm), indent=2, sort_keys=True))
    except GremlinChatError as exc:
        raise SystemExit(str(exc)) from exc


def trial_simulate_command(args: argparse.Namespace) -> None:
    report_home = None if args.no_report else _home(args.home)
    report = run_trial_simulation(write_report_home=report_home)
    print(json.dumps(report, indent=2, sort_keys=True))
    if not report["ok"]:
        raise SystemExit(1)


def trial_report_command(args: argparse.Namespace) -> None:
    home = _home(args.home)
    if args.summary_json:
        summary = json.loads(args.summary_json)
    else:
        summary = current_trial_snapshot(home)
    paths = write_trial_report(home, summary)
    print(json.dumps({"report_paths": paths}, indent=2, sort_keys=True))


def _load_room(home: Path, room_id: str | None) -> dict:
    try:
        return load_room_state(home, room_id)
    except GremlinChatError as exc:
        raise SystemExit(str(exc)) from exc


def _require_room_verified(room: dict) -> None:
    try:
        require_room_verified_state(room)
    except GremlinChatError as exc:
        raise SystemExit(str(exc)) from exc


def _fetch_room_messages(room: dict) -> list[dict]:
    try:
        return fetch_room_messages_state(room)
    except GremlinChatError as exc:
        raise SystemExit(str(exc)) from exc


def _room_key(room: dict, identity, x25519_identity) -> bytes:
    try:
        return room_key_state(room, identity, x25519_identity)
    except GremlinChatError as exc:
        raise SystemExit(str(exc)) from exc


def _owner_rejected_result(runbook: str) -> dict:
    return owner_rejected_result_state(runbook)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="gremlinchat", description="GremlinChat private control room")
    parser.add_argument("--home", default=None, help="Config directory. Defaults to LOCALAPPDATA/GremlinChat.")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("setup", help="Create local identity and default policy").set_defaults(func=setup)
    subcommands.add_parser("status", help="Show local status").set_defaults(func=show_status)
    subcommands.add_parser("emergency-stop", help="Disable all remote runbook requests").set_defaults(func=emergency_stop)

    install_parser = subcommands.add_parser("install", help="Installer and local readiness commands")
    install_subcommands = install_parser.add_subparsers(dest="install_command", required=True)
    install_doctor = install_subcommands.add_parser("doctor", help="Check local installer/runtime readiness")
    install_doctor.add_argument("--write-report", action="store_true", help="Write a redacted install doctor report under the local reports folder")
    install_doctor.set_defaults(func=install_doctor_command)

    receipt_parser = subcommands.add_parser("receipt", help="Trust Receipt commands")
    receipt_subcommands = receipt_parser.add_subparsers(dest="receipt_command", required=True)
    receipt_list = receipt_subcommands.add_parser("list", help="List signed Trust Receipts")
    receipt_list.add_argument("--limit", default=25, type=int)
    receipt_list.add_argument("--partner", action="store_true", help="List imported partner receipts instead of local receipts")
    receipt_list.set_defaults(func=receipt_list_command)
    receipt_show = receipt_subcommands.add_parser("show", help="Show one Trust Receipt by id or path")
    receipt_show.add_argument("receipt")
    receipt_show.set_defaults(func=receipt_show_command)
    receipt_verify = receipt_subcommands.add_parser("verify", help="Verify one Trust Receipt JSON file")
    receipt_verify.add_argument("path")
    receipt_verify.set_defaults(func=receipt_verify_command)
    receipt_verify_bundle = receipt_subcommands.add_parser("verify-bundle", help="Verify every Trust Receipt in a bundle")
    receipt_verify_bundle.add_argument("path")
    receipt_verify_bundle.set_defaults(func=receipt_verify_bundle_command)
    receipt_import = receipt_subcommands.add_parser("import", help="Verify and import a partner receipt or receipt bundle")
    receipt_import.add_argument("path")
    receipt_import.set_defaults(func=receipt_import_command)
    receipt_compare = receipt_subcommands.add_parser("compare", help="Compare local and imported partner receipt evidence")
    receipt_compare.add_argument("--room-id", default=None)
    receipt_compare.add_argument("--strict", action="store_true", help="Exit non-zero when evidence is missing or mismatched")
    receipt_compare.set_defaults(func=receipt_compare_command)
    receipt_bundle = receipt_subcommands.add_parser("bundle", help="Write a redacted Trust Receipt bundle")
    receipt_bundle.add_argument("--room-id", default=None)
    receipt_bundle.set_defaults(func=receipt_bundle_command)

    daemon_parser = subcommands.add_parser("daemon", help="Local dashboard commands")
    daemon_subcommands = daemon_parser.add_subparsers(dest="daemon_command", required=True)
    daemon_serve = daemon_subcommands.add_parser("serve", help="Serve the local dashboard")
    daemon_serve.add_argument("--host", default="127.0.0.1")
    daemon_serve.add_argument("--port", default=8777, type=int)
    daemon_serve.set_defaults(func=serve_daemon)

    relay_parser = subcommands.add_parser("relay", help="Relay commands")
    relay_subcommands = relay_parser.add_subparsers(dest="relay_command", required=True)
    relay_serve = relay_subcommands.add_parser("serve", help="Serve a relay")
    relay_serve.add_argument("--host", default="127.0.0.1")
    relay_serve.add_argument("--port", default=8778, type=int)
    relay_serve.add_argument("--state-dir", default=None, help="Optional directory for persistent relay state.")
    relay_serve.add_argument("--max-body-bytes", default=256 * 1024, type=int, help="Reject HTTP request bodies above this size.")
    relay_serve.add_argument("--max-envelope-bytes", default=128 * 1024, type=int, help="Reject encrypted envelopes above this size.")
    relay_serve.add_argument("--max-messages-per-room", default=1000, type=int, help="Reject new messages after this many room messages.")
    relay_serve.set_defaults(func=serve_relay)

    pair_parser = subcommands.add_parser("pair", help="Guided first-run pairing ceremony")
    pair_subcommands = pair_parser.add_subparsers(dest="pair_command", required=True)
    pair_host_parser = pair_subcommands.add_parser("host", help="Create a private invite and register this host with the relay")
    pair_host_parser.add_argument("--relay", required=True, help="Relay URL, such as http://100.x.y.z:8778")
    pair_host_parser.add_argument("--ttl-seconds", default=600, type=int)
    pair_host_parser.set_defaults(func=pair_host_command)
    pair_join_parser = pair_subcommands.add_parser("join", help="Join from a GC1 invite and post a signed pairing hello")
    pair_join_parser.add_argument("code")
    pair_join_parser.set_defaults(func=pair_join_command)
    pair_verify_parser = pair_subcommands.add_parser("verify", help="Enable a room after comparing the safety phrase out of band")
    pair_verify_parser.add_argument("--room-id", default=None)
    pair_verify_parser.add_argument("--phrase", required=True)
    pair_verify_parser.set_defaults(func=pair_verify_command)
    pair_status_parser = pair_subcommands.add_parser("status", help="Show pairing ceremony state and next commands")
    pair_status_parser.add_argument("--show-invite", action="store_true", help="Show the latest unexpired local invite code")
    pair_status_parser.set_defaults(func=pair_status_command)

    room_parser = subcommands.add_parser("room", help="Pairing room commands")
    room_subcommands = room_parser.add_subparsers(dest="room_command", required=True)
    room_create = room_subcommands.add_parser("create", help="Create a one-time invite code")
    room_create.add_argument("--relay", default="http://127.0.0.1:8778")
    room_create.add_argument("--ttl-seconds", default=600, type=int)
    room_create.set_defaults(func=create_room)
    room_join = room_subcommands.add_parser("join", help="Join a room from a GC1 invite code")
    room_join.add_argument("code")
    room_join.set_defaults(func=join_room)
    room_sync = room_subcommands.add_parser("sync", help="Fetch pairing hellos and encrypted room messages")
    room_sync.add_argument("--room-id", default=None)
    room_sync.set_defaults(func=sync_room)
    room_verify = room_subcommands.add_parser("verify", help="Activate a room after comparing the safety phrase")
    room_verify.add_argument("--room-id", default=None)
    room_verify.add_argument("--phrase", required=True)
    room_verify.set_defaults(func=verify_room)
    room_disable = room_subcommands.add_parser("disable", help="Disable a room until it is verified again")
    room_disable.add_argument("--room-id", default=None)
    room_disable.set_defaults(func=disable_room)
    room_revoke = room_subcommands.add_parser("revoke", help="Revoke a paired peer and disable the room")
    room_revoke.add_argument("--room-id", default=None)
    room_revoke.set_defaults(func=revoke_room)
    room_request = room_subcommands.add_parser("request", help="Send an encrypted runbook request")
    room_request.add_argument("--room-id", default=None)
    room_request.add_argument("--runbook", required=True)
    room_request.add_argument("--payload-json", default="{}")
    room_request.set_defaults(func=request_runbook)
    room_process = room_subcommands.add_parser("process", help="Process encrypted runbook requests")
    room_process.add_argument("--room-id", default=None)
    room_process.set_defaults(func=process_room)
    room_loop = room_subcommands.add_parser("loop", help="Continuously process encrypted runbook requests")
    room_loop.add_argument("--room-id", default=None)
    room_loop.add_argument("--interval", default=5.0, type=float)
    room_loop.add_argument("--max-iterations", default=None, type=int)
    room_loop.add_argument("--stop-when-idle", action="store_true")
    room_loop.set_defaults(func=loop_room)

    runbook_parser = subcommands.add_parser("runbook", help="Runbook commands")
    runbook_subcommands = runbook_parser.add_subparsers(dest="runbook_command", required=True)
    runbook_subcommands.add_parser("list", help="List runbooks and policy").set_defaults(func=list_runbooks)
    runbook_run = runbook_subcommands.add_parser("run", help="Run one local runbook")
    runbook_run.add_argument("name")
    runbook_run.add_argument("--payload-json", default="{}")
    runbook_run.add_argument("--requester-node-id", default=None)
    runbook_run.set_defaults(func=run_runbook)
    approve = runbook_subcommands.add_parser("approve-repo", help="Approve one repo path")
    approve.add_argument("--name", required=True)
    approve.add_argument("--path", required=True)
    approve.add_argument("--allow-pull", action="store_true")
    approve.add_argument("--allow-test", action="append", default=[])
    approve.set_defaults(func=approve_repo)

    approval_parser = subcommands.add_parser("approval", help="Owner approval commands")
    approval_subcommands = approval_parser.add_subparsers(dest="approval_command", required=True)
    approval_subcommands.add_parser("list", help="List approvals").set_defaults(func=list_approvals_command)
    approval_approve = approval_subcommands.add_parser("approve", help="Approve request")
    approval_approve.add_argument("approval_id")
    approval_approve.set_defaults(func=decide_approval_command)
    approval_reject = approval_subcommands.add_parser("reject", help="Reject request")
    approval_reject.add_argument("approval_id")
    approval_reject.set_defaults(func=decide_approval_command)

    trial_parser = subcommands.add_parser("trial", help="Read-only reliability trial commands")
    trial_subcommands = trial_parser.add_subparsers(dest="trial_command", required=True)
    trial_preflight = trial_subcommands.add_parser("preflight", help="Check whether this machine is ready for the private read-only trial")
    trial_preflight.add_argument("--relay", default=None, help="Relay URL to check, such as http://100.x.y.z:8778")
    trial_preflight.add_argument("--dashboard-port", default=8777, type=int)
    trial_preflight.add_argument("--relay-port", default=8778, type=int)
    trial_preflight.add_argument("--write-report", action="store_true", help="Write a redacted trial report under the local GremlinChat reports folder")
    trial_preflight.set_defaults(func=trial_preflight_command)
    trial_host = trial_subcommands.add_parser("host", help="Create a private invite for a live two-machine read-only trial")
    trial_host.add_argument("--relay", required=True, help="Relay URL, such as http://100.x.y.z:8778")
    trial_host.add_argument("--ttl-seconds", default=600, type=int)
    trial_host.set_defaults(func=trial_host_command)
    trial_guest = trial_subcommands.add_parser("guest", help="Join a live two-machine read-only trial from a GC1 invite code")
    trial_guest.add_argument("code")
    trial_guest.set_defaults(func=trial_guest_command)
    trial_host_session = trial_subcommands.add_parser("host-session", help="Run host preflight and create one invite only if needed")
    trial_host_session.add_argument("--relay", required=True, help="Relay URL, such as http://100.x.y.z:8778")
    trial_host_session.add_argument("--ttl-seconds", default=600, type=int)
    trial_host_session.set_defaults(func=trial_host_session_command)
    trial_guest_session = trial_subcommands.add_parser("guest-session", help="Run guest preflight and join one invite only if needed")
    trial_guest_session.add_argument("code")
    trial_guest_session.set_defaults(func=trial_guest_session_command)
    trial_prove = trial_subcommands.add_parser("prove", help="Send the read-only proof runbooks and wait for results")
    trial_prove.add_argument("--room-id", default=None)
    trial_prove.add_argument("--timeout-seconds", default=30.0, type=float)
    trial_prove.add_argument("--interval", default=2.0, type=float)
    trial_prove.add_argument("--no-report", action="store_true", help="Do not write a redacted proof report")
    trial_prove.set_defaults(func=trial_prove_command)
    trial_listen = trial_subcommands.add_parser("listen", help="Process live trial requests with the read-only lock enforced")
    trial_listen.add_argument("--room-id", default=None)
    trial_listen.add_argument("--interval", default=5.0, type=float)
    trial_listen.add_argument("--max-iterations", default=None, type=int)
    trial_listen.add_argument("--stop-when-idle", action="store_true")
    trial_listen.set_defaults(func=trial_listen_command)
    trial_checklist = trial_subcommands.add_parser("checklist", help="Show exact next commands for the live trial")
    trial_checklist.add_argument("--role", required=True, choices=["host", "guest"])
    trial_checklist.add_argument("--relay", default=None, help="Relay URL to include in host guidance")
    trial_checklist.set_defaults(func=trial_checklist_command)
    trial_bundle = trial_subcommands.add_parser("bundle", help="Write a redacted support bundle for trial debugging")
    trial_bundle.add_argument("--relay", default=None, help="Optional relay URL to include a health check")
    trial_bundle.set_defaults(func=trial_bundle_command)
    trial_reset = trial_subcommands.add_parser("reset-local", help="Clear local trial rooms, approvals, and reports while preserving identity")
    trial_reset.add_argument("--confirm", required=True, help=f"Must be {RESET_CONFIRMATION}")
    trial_reset.set_defaults(func=trial_reset_local_command)
    trial_simulate = trial_subcommands.add_parser("simulate", help="Run a local two-client read-only proof through a relay")
    trial_simulate.add_argument("--no-report", action="store_true", help="Do not write a local trial report")
    trial_simulate.set_defaults(func=trial_simulate_command)
    trial_report = trial_subcommands.add_parser("report", help="Write a redacted local trial report")
    trial_report.add_argument("--summary-json", default=None, help="Optional JSON summary to write instead of a live local snapshot")
    trial_report.set_defaults(func=trial_report_command)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
