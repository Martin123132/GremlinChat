"""GremlinChat command line interface."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from .crypto import (
    EncryptedEnvelope,
    ReplayGuard,
    derive_room_key,
    open_message,
    parse_invite_code,
    safety_phrase,
    seal_message,
    create_invite_code,
)
from .daemon import create_daemon_http_server
from .messages import create_pair_hello, create_task_request, create_task_result, verify_pair_hello
from .relay import RelayClient, create_relay_http_server
from .runbooks import check_runbook_approval, execute_runbook, runbook_catalog, runbook_result_json
from .store import (
    ApprovedRepo,
    RunbookPolicy,
    approval_for_task,
    create_pending_approval,
    decide_approval,
    default_home,
    ensure_home,
    load_approvals,
    load_or_create_identity,
    load_or_create_x25519_identity,
    load_policy,
    load_rooms,
    mark_approval_consumed,
    save_policy,
    save_room,
    write_task_report,
)


def _home(raw: str | None) -> Path:
    return ensure_home(default_home() if raw is None else Path(raw))


def setup(args: argparse.Namespace) -> None:
    home = _home(args.home)
    identity = load_or_create_identity(home)
    x25519_identity = load_or_create_x25519_identity(home)
    print(json.dumps({"configured": True, "home": str(home), "node_id": identity.node_id, "public_key": identity.public_key, "x25519_public_key": x25519_identity.public_key, "policy": runbook_catalog(load_policy(home))}, indent=2, sort_keys=True))


def serve_relay(args: argparse.Namespace) -> None:
    server = create_relay_http_server(host=args.host, port=args.port)
    print(f"GremlinChat relay listening: http://{args.host}:{args.port}")
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
    home = _home(args.home)
    identity = load_or_create_identity(home)
    x25519_identity = load_or_create_x25519_identity(home)
    room_response = RelayClient(args.relay).create_room(ttl_seconds=args.ttl_seconds)
    if "room_id" not in room_response:
        raise SystemExit(f"relay room creation failed: {room_response}")
    invite_code = create_invite_code(
        creator=identity,
        creator_x25519_public_key=x25519_identity.public_key,
        relay_url=args.relay,
        room_id=room_response["room_id"],
        relay_token=room_response["relay_token"],
        ttl_seconds=args.ttl_seconds,
    )
    invite = parse_invite_code(invite_code)
    save_room(
        {
            "room_id": invite.room_id,
            "relay_url": invite.relay_url,
            "relay_token": invite.relay_token,
            "pair_secret": invite.pair_secret,
            "local_x25519_public_key": x25519_identity.public_key,
            "created_by": identity.node_id,
            "created_at": round(time.time(), 3),
            "expires_at": invite.expires_at,
            "verified": False,
            "processed_message_ids": [],
        },
        home,
    )
    print(json.dumps({"room_id": invite.room_id, "relay_url": invite.relay_url, "expires_at": invite.expires_at, "invite_code": invite_code, "note": "Share privately. Do not commit invite codes."}, indent=2, sort_keys=True))


def join_room(args: argparse.Namespace) -> None:
    home = _home(args.home)
    identity = load_or_create_identity(home)
    x25519_identity = load_or_create_x25519_identity(home)
    invite = parse_invite_code(args.code)
    phrase = safety_phrase(invite.pair_secret, [invite.creator_public_key, identity.public_key])
    save_room(
        {
            "room_id": invite.room_id,
            "relay_url": invite.relay_url,
            "relay_token": invite.relay_token,
            "pair_secret": invite.pair_secret,
            "peer_node_id": invite.creator_node_id,
            "peer_public_key": invite.creator_public_key,
            "peer_x25519_public_key": invite.creator_x25519_public_key,
            "local_x25519_public_key": x25519_identity.public_key,
            "joined_by": identity.node_id,
            "joined_at": round(time.time(), 3),
            "expires_at": invite.expires_at,
            "safety_phrase": phrase,
            "verified": False,
            "processed_message_ids": [],
        },
        home,
    )
    hello_response = RelayClient(invite.relay_url).post_envelope(
        room_id=invite.room_id,
        relay_token=invite.relay_token,
        envelope=create_pair_hello(room_id=invite.room_id, sender=identity, x25519_public_key=x25519_identity.public_key),
    )
    print(json.dumps({"joined": True, "room_id": invite.room_id, "relay_url": invite.relay_url, "peer_node_id": invite.creator_node_id, "safety_phrase": phrase, "hello_posted": hello_response.get("accepted") is True}, indent=2, sort_keys=True))


def sync_room(args: argparse.Namespace) -> None:
    home = _home(args.home)
    identity = load_or_create_identity(home)
    x25519_identity = load_or_create_x25519_identity(home)
    room = _load_room(home, args.room_id)
    messages = _fetch_room_messages(room)
    decrypted = []
    updated = False
    for record in messages:
        envelope = record["envelope"]
        if envelope.get("protocol") == "gremlinchat.pair-hello.v1":
            if envelope.get("sender_node_id") != identity.node_id and verify_pair_hello(envelope):
                room["peer_node_id"] = envelope["sender_node_id"]
                room["peer_public_key"] = envelope["sender_public_key"]
                room["peer_x25519_public_key"] = envelope["x25519_public_key"]
                room["safety_phrase"] = safety_phrase(room["pair_secret"], [identity.public_key, envelope["sender_public_key"]])
                updated = True
            continue
        if envelope.get("sender_node_id") == identity.node_id or "peer_x25519_public_key" not in room:
            continue
        try:
            message = open_message(envelope=EncryptedEnvelope.from_dict(envelope), room_key=_room_key(room, identity, x25519_identity), replay_guard=ReplayGuard())
            if message.get("type") == "task.result.v1":
                message["report_paths"] = write_task_report(home, message)
            decrypted.append(message)
        except ValueError as exc:
            decrypted.append({"type": "message.error", "error": str(exc)})
    if updated:
        save_room(room, home)
    print(json.dumps({"room_id": room["room_id"], "peer_node_id": room.get("peer_node_id"), "safety_phrase": room.get("safety_phrase"), "message_count": len(messages), "decrypted_messages": decrypted}, indent=2, sort_keys=True))


def request_runbook(args: argparse.Namespace) -> None:
    home = _home(args.home)
    identity = load_or_create_identity(home)
    x25519_identity = load_or_create_x25519_identity(home)
    room = _load_room(home, args.room_id)
    request = create_task_request(runbook=args.runbook, payload=json.loads(args.payload_json or "{}"))
    envelope = seal_message(room_id=room["room_id"], sender=identity, room_key=_room_key(room, identity, x25519_identity), message=request)
    response = RelayClient(room["relay_url"]).post_envelope(room_id=room["room_id"], relay_token=room["relay_token"], envelope=envelope.to_dict())
    print(json.dumps({"task_id": request["task_id"], "relay_response": response}, indent=2, sort_keys=True))


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
    identity = load_or_create_identity(home)
    x25519_identity = load_or_create_x25519_identity(home)
    policy = load_policy(home)
    room = _load_room(home, room_id)
    processed = set(room.get("processed_message_ids", []))
    replies = []
    for record in _fetch_room_messages(room):
        envelope_data = record["envelope"]
        if envelope_data.get("protocol") != "gremlinchat.envelope.v1" or envelope_data.get("sender_node_id") == identity.node_id:
            continue
        message_id = envelope_data.get("message_id")
        if message_id in processed:
            continue
        message = open_message(envelope=EncryptedEnvelope.from_dict(envelope_data), room_key=_room_key(room, identity, x25519_identity), replay_guard=ReplayGuard())
        if message.get("type") != "task.request.v1":
            continue
        requester_node_id = str(envelope_data.get("sender_node_id"))
        payload = dict(message.get("payload", {}))
        runbook = str(message["runbook"])
        existing_approval = approval_for_task(home, str(message["task_id"]))
        approval_override = existing_approval is not None and existing_approval.get("status") == "approved"
        if existing_approval and existing_approval.get("status") == "rejected":
            result_dict = _owner_rejected_result(runbook)
        elif not approval_override:
            approval_check = check_runbook_approval(runbook, payload, policy=policy, requester_node_id=requester_node_id)
            if approval_check.status == "pending":
                approval = create_pending_approval(home, room_id=room["room_id"], task_id=str(message["task_id"]), requester_node_id=requester_node_id, runbook=runbook, payload=payload, reason=approval_check.reason)
                replies.append({"task_id": message["task_id"], "runbook": runbook, "status": "pending_approval", "approval_id": approval["approval_id"]})
                continue
            result_dict = execute_runbook(runbook, payload, policy=policy, home=home, requester_node_id=requester_node_id).to_dict()
        else:
            result_dict = execute_runbook(runbook, payload, policy=policy, home=home, requester_node_id=requester_node_id, approval_override=True).to_dict()
        reply = create_task_result(request=message, result=result_dict)
        reply_envelope = seal_message(room_id=room["room_id"], sender=identity, room_key=_room_key(room, identity, x25519_identity), message=reply)
        relay_response = RelayClient(room["relay_url"]).post_envelope(room_id=room["room_id"], relay_token=room["relay_token"], envelope=reply_envelope.to_dict())
        if existing_approval:
            mark_approval_consumed(home, str(existing_approval["approval_id"]))
        report_paths = write_task_report(home, {"direction": "outgoing", "task_id": message["task_id"], "runbook": runbook, "result": result_dict, "relay_response": relay_response})
        processed.add(str(message_id))
        replies.append({"task_id": message["task_id"], "runbook": runbook, "relay_response": relay_response, "report_paths": report_paths})
    room["processed_message_ids"] = sorted(processed)
    save_room(room, home)
    return {"processed": replies, "count": len(replies)}


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
    print(json.dumps({"emergency_stop": True, "home": str(home)}, indent=2, sort_keys=True))


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


def _load_room(home: Path, room_id: str | None) -> dict:
    rooms = load_rooms(home)
    if room_id is None:
        if len(rooms) != 1:
            raise SystemExit("Pass --room-id when there is not exactly one GremlinChat room.")
        return rooms[0]
    for room in rooms:
        if room.get("room_id") == room_id:
            return room
    raise SystemExit(f"Unknown GremlinChat room: {room_id}")


def _fetch_room_messages(room: dict) -> list[dict]:
    response = RelayClient(room["relay_url"]).messages_after(room_id=room["room_id"], relay_token=room["relay_token"], after=-1)
    if "messages" not in response:
        raise SystemExit(f"Could not fetch room messages: {response}")
    return list(response["messages"])


def _room_key(room: dict, identity, x25519_identity) -> bytes:
    peer_x25519 = room.get("peer_x25519_public_key")
    peer_public = room.get("peer_public_key")
    if not peer_x25519 or not peer_public:
        raise SystemExit("Room is not ready; run gremlinchat room sync after the partner joins.")
    return derive_room_key(local_private_key=x25519_identity.private_key, peer_public_key=peer_x25519, pair_secret=room["pair_secret"], participant_public_keys=[identity.public_key, peer_public])


def _owner_rejected_result(runbook: str) -> dict:
    timestamp = round(time.time(), 3)
    return {"accepted": False, "runbook": runbook, "status": "rejected", "summary": "Local owner rejected this GremlinChat request.", "output": {"error": "owner_rejected"}, "started_at": timestamp, "completed_at": timestamp}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="gremlinchat", description="GremlinChat private control room")
    parser.add_argument("--home", default=None, help="Config directory. Defaults to LOCALAPPDATA/GremlinChat.")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("setup", help="Create local identity and default policy").set_defaults(func=setup)
    subcommands.add_parser("status", help="Show local status").set_defaults(func=show_status)
    subcommands.add_parser("emergency-stop", help="Disable all remote runbook requests").set_defaults(func=emergency_stop)

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
    relay_serve.set_defaults(func=serve_relay)

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
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

