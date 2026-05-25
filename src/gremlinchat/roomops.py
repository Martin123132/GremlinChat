"""Shared room operations for the CLI, dashboard, and trial runner."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from .crypto import EncryptedEnvelope, ReplayGuard, derive_room_key, open_message, safety_phrase, seal_message
from .messages import create_task_request, create_task_result, verify_pair_hello
from .receipts import create_receipt
from .relay import RelayClient
from .runbooks import ALL_RUNBOOKS, WRITE_RUNBOOKS, check_runbook_approval, execute_runbook
from .store import (
    approval_for_task,
    append_audit_event,
    create_pending_approval,
    load_or_create_identity,
    load_or_create_x25519_identity,
    load_policy,
    load_rooms,
    mark_approval_consumed,
    save_policy,
    save_room,
    write_task_report,
)


class GremlinChatError(Exception):
    """Expected operational error that should be shown without a traceback."""


def load_room(home: Path, room_id: str | None) -> dict[str, Any]:
    rooms = load_rooms(home)
    if room_id is None:
        if len(rooms) != 1:
            raise GremlinChatError("Pass --room-id when there is not exactly one GremlinChat room.")
        return rooms[0]
    for room in rooms:
        if room.get("room_id") == room_id:
            return room
    raise GremlinChatError(f"Unknown GremlinChat room: {room_id}")


def require_room_verified(room: dict[str, Any]) -> None:
    if room.get("disabled"):
        raise GremlinChatError("Room is disabled. Run room verify again only after confirming consent.")
    if not room.get("verified"):
        raise GremlinChatError("Room is not verified. Compare the safety phrase with the other person, then run gremlinchat room verify --phrase <phrase>.")
    if not room.get("peer_node_id") or not room.get("peer_public_key") or not room.get("peer_x25519_public_key"):
        raise GremlinChatError("Room is missing peer identity. Run gremlinchat room sync before verification.")


def sync_room_messages(home: Path, room_id: str | None) -> dict[str, Any]:
    identity = load_or_create_identity(home)
    x25519_identity = load_or_create_x25519_identity(home)
    room = load_room(home, room_id)
    messages = fetch_room_messages(room)
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
            message = open_message(envelope=EncryptedEnvelope.from_dict(envelope), room_key=room_key(room, identity, x25519_identity), replay_guard=ReplayGuard())
            if message.get("type") == "task.result.v1":
                message["report_paths"] = write_task_report(home, message)
                result = dict(message.get("result", {}))
                create_receipt(
                    home,
                    event_type="task.result",
                    status=str(result.get("status", "received")),
                    room_id=room["room_id"],
                    task_id=str(message.get("task_id", "")),
                    runbook=str(message.get("runbook", "")),
                    dedupe_key=f"incoming:{message.get('task_id')}",
                    evidence={
                        "direction": "incoming",
                        "peer_node_id": envelope.get("sender_node_id"),
                        "accepted": bool(result.get("accepted", False)),
                        "summary": result.get("summary", ""),
                        "report_paths": message["report_paths"],
                    },
                )
            decrypted.append(message)
        except ValueError as exc:
            decrypted.append({"type": "message.error", "error": str(exc)})
    if updated:
        save_room(room, home)
    return {"room_id": room["room_id"], "peer_node_id": room.get("peer_node_id"), "safety_phrase": room.get("safety_phrase"), "message_count": len(messages), "decrypted_messages": decrypted}


def verify_room(home: Path, room_id: str | None, phrase: str) -> dict[str, Any]:
    room = load_room(home, room_id)
    expected = str(room.get("safety_phrase") or "")
    supplied = str(phrase or "").strip()
    if not expected:
        raise GremlinChatError("Room does not have a safety phrase yet. Run gremlinchat room sync first.")
    if supplied != expected:
        raise GremlinChatError("Safety phrase mismatch. Do not activate this room.")
    if not room.get("peer_node_id") or not room.get("peer_public_key") or not room.get("peer_x25519_public_key"):
        raise GremlinChatError("Room does not have complete peer identity yet. Run gremlinchat room sync first.")
    room["verified"] = True
    room["disabled"] = False
    room["verified_at"] = round(time.time(), 3)
    save_room(room, home)
    append_audit_event(home, {"event_type": "room.verified", "room_id": room["room_id"], "peer_node_id": room.get("peer_node_id")})
    create_receipt(
        home,
        event_type="room.verified",
        status="verified",
        room_id=room["room_id"],
        dedupe_key=f"room.verified:{room['room_id']}:{room.get('peer_node_id')}:{room['verified_at']}",
        evidence={"room_id": room["room_id"], "peer_node_id": room.get("peer_node_id"), "verified_at": room["verified_at"]},
    )
    return {"verified": True, "room_id": room["room_id"], "safety_phrase": expected}


def disable_room(home: Path, room_id: str | None) -> dict[str, Any]:
    room = load_room(home, room_id)
    room["verified"] = False
    room["disabled"] = True
    room["disabled_at"] = round(time.time(), 3)
    save_room(room, home)
    append_audit_event(home, {"event_type": "room.disabled", "room_id": room["room_id"], "peer_node_id": room.get("peer_node_id")})
    create_receipt(
        home,
        event_type="room.disabled",
        status="disabled",
        room_id=room["room_id"],
        dedupe_key=f"room.disabled:{room['room_id']}:{room['disabled_at']}",
        evidence={"room_id": room["room_id"], "peer_node_id": room.get("peer_node_id"), "disabled_at": room["disabled_at"]},
    )
    return {"disabled": True, "room_id": room["room_id"]}


def revoke_room(home: Path, room_id: str | None) -> dict[str, Any]:
    room = load_room(home, room_id)
    peer_node_id = str(room.get("peer_node_id") or "")
    room["verified"] = False
    room["disabled"] = True
    room["revoked_at"] = round(time.time(), 3)
    save_room(room, home)
    policy = load_policy(home)
    if peer_node_id and peer_node_id not in policy.revoked_node_ids:
        policy.revoked_node_ids.append(peer_node_id)
        save_policy(policy, home)
    append_audit_event(home, {"event_type": "room.revoked", "room_id": room["room_id"], "peer_node_id": peer_node_id or None})
    create_receipt(
        home,
        event_type="room.revoked",
        status="revoked",
        room_id=room["room_id"],
        dedupe_key=f"room.revoked:{room['room_id']}:{room['revoked_at']}",
        evidence={"room_id": room["room_id"], "peer_node_id": peer_node_id or None, "revoked_at": room["revoked_at"]},
    )
    return {"revoked": True, "room_id": room["room_id"], "peer_node_id": peer_node_id or None}


def request_runbook(home: Path, room_id: str | None, runbook: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    identity = load_or_create_identity(home)
    x25519_identity = load_or_create_x25519_identity(home)
    policy = load_policy(home)
    room = load_room(home, room_id)
    require_room_verified(room)
    if policy.emergency_stop:
        raise GremlinChatError("Emergency stop is active; remote runbook requests are disabled.")
    if room.get("peer_node_id") in policy.revoked_node_ids:
        raise GremlinChatError("This room's peer has been revoked.")
    if runbook not in ALL_RUNBOOKS:
        raise GremlinChatError(f"Unknown or arbitrary command rejected: {runbook}")
    if runbook in WRITE_RUNBOOKS and policy.trial_read_only_lock:
        raise GremlinChatError("Trial read-only lock is active; write-capable runbooks are disabled.")
    request = create_task_request(runbook=runbook, payload={} if payload is None else payload)
    envelope = seal_message(room_id=room["room_id"], sender=identity, room_key=room_key(room, identity, x25519_identity), message=request)
    response = RelayClient(room["relay_url"]).post_envelope(room_id=room["room_id"], relay_token=room["relay_token"], envelope=envelope.to_dict())
    append_audit_event(home, {"event_type": "task.requested", "room_id": room["room_id"], "task_id": request["task_id"], "runbook": runbook, "relay_response": response})
    create_receipt(
        home,
        event_type="task.requested",
        status="accepted" if response.get("accepted") else "relay_rejected",
        room_id=room["room_id"],
        task_id=request["task_id"],
        runbook=runbook,
        dedupe_key=f"task.requested:{request['task_id']}",
        evidence={"peer_node_id": room.get("peer_node_id"), "relay_response": response},
    )
    return {"task_id": request["task_id"], "relay_response": response}


def process_room_once(home: Path, room_id: str | None) -> dict[str, Any]:
    identity = load_or_create_identity(home)
    x25519_identity = load_or_create_x25519_identity(home)
    policy = load_policy(home)
    room = load_room(home, room_id)
    require_room_verified(room)
    processed = set(room.get("processed_message_ids", []))
    replies = []
    for record in fetch_room_messages(room):
        envelope_data = record["envelope"]
        if envelope_data.get("protocol") != "gremlinchat.envelope.v1" or envelope_data.get("sender_node_id") == identity.node_id:
            continue
        message_id = envelope_data.get("message_id")
        if message_id in processed:
            continue
        message = open_message(envelope=EncryptedEnvelope.from_dict(envelope_data), room_key=room_key(room, identity, x25519_identity), replay_guard=ReplayGuard())
        if message.get("type") != "task.request.v1":
            continue
        requester_node_id = str(envelope_data.get("sender_node_id"))
        payload = dict(message.get("payload", {}))
        runbook = str(message["runbook"])
        existing_approval = approval_for_task(home, str(message["task_id"]))
        approval_override = existing_approval is not None and existing_approval.get("status") == "approved"
        if existing_approval and existing_approval.get("status") == "rejected":
            result_dict = owner_rejected_result(runbook)
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
        reply_envelope = seal_message(room_id=room["room_id"], sender=identity, room_key=room_key(room, identity, x25519_identity), message=reply)
        relay_response = RelayClient(room["relay_url"]).post_envelope(room_id=room["room_id"], relay_token=room["relay_token"], envelope=reply_envelope.to_dict())
        if existing_approval:
            mark_approval_consumed(home, str(existing_approval["approval_id"]))
        report_paths = write_task_report(home, {"direction": "outgoing", "task_id": message["task_id"], "runbook": runbook, "result": result_dict, "relay_response": relay_response})
        create_receipt(
            home,
            event_type="task.result",
            status=str(result_dict.get("status", "returned")),
            room_id=room["room_id"],
            task_id=str(message["task_id"]),
            runbook=runbook,
            dedupe_key=f"outgoing:{message['task_id']}",
            evidence={
                "direction": "outgoing",
                "requester_node_id": requester_node_id,
                "accepted": bool(result_dict.get("accepted", False)),
                "summary": result_dict.get("summary", ""),
                "relay_response": relay_response,
                "report_paths": report_paths,
            },
        )
        processed.add(str(message_id))
        replies.append({"task_id": message["task_id"], "runbook": runbook, "relay_response": relay_response, "report_paths": report_paths})
    room["processed_message_ids"] = sorted(processed)
    save_room(room, home)
    return {"processed": replies, "count": len(replies)}


def fetch_room_messages(room: dict[str, Any]) -> list[dict[str, Any]]:
    response = RelayClient(room["relay_url"]).messages_after(room_id=room["room_id"], relay_token=room["relay_token"], after=-1)
    if "messages" not in response:
        raise GremlinChatError(f"Could not fetch room messages: {response}")
    return list(response["messages"])


def room_key(room: dict[str, Any], identity: Any, x25519_identity: Any) -> bytes:
    peer_x25519 = room.get("peer_x25519_public_key")
    peer_public = room.get("peer_public_key")
    if not peer_x25519 or not peer_public:
        raise GremlinChatError("Room is not ready; run gremlinchat room sync after the partner joins.")
    return derive_room_key(local_private_key=x25519_identity.private_key, peer_public_key=peer_x25519, pair_secret=room["pair_secret"], participant_public_keys=[identity.public_key, peer_public])


def owner_rejected_result(runbook: str) -> dict[str, Any]:
    timestamp = round(time.time(), 3)
    return {"accepted": False, "runbook": runbook, "status": "rejected", "summary": "Local owner rejected this GremlinChat request.", "output": {"error": "owner_rejected"}, "started_at": timestamp, "completed_at": timestamp}
