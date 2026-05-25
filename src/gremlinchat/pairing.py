"""Guided first-run pairing ceremony helpers."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .crypto import create_invite_code, parse_invite_code, protect_secret, safety_phrase, unprotect_secret
from .messages import create_pair_hello
from .receipts import create_receipt
from .relay import RelayClient
from .roomops import GremlinChatError, verify_room
from .store import append_audit_event, ensure_home, load_or_create_identity, load_or_create_x25519_identity, load_policy, load_rooms, save_policy, save_room

PAIRING_INVITE_FILE = "pairing-latest-invite.json"


def pair_host(
    home: Path,
    *,
    relay_url: str,
    ttl_seconds: int = 600,
    read_only_lock: bool = True,
    allow_existing: bool = False,
) -> dict[str, Any]:
    home = ensure_home(home)
    if read_only_lock:
        _ensure_read_only_lock(home)
    if not allow_existing and _active_rooms(home):
        raise GremlinChatError("An active pairing room already exists. Revoke, disable, or reset it before creating another invite.")

    identity = load_or_create_identity(home)
    x25519_identity = load_or_create_x25519_identity(home)
    room_response = RelayClient(relay_url).create_room(ttl_seconds=ttl_seconds)
    if "room_id" not in room_response:
        raise GremlinChatError(f"relay room creation failed: {room_response}")

    invite_code = create_invite_code(
        creator=identity,
        creator_x25519_public_key=x25519_identity.public_key,
        relay_url=relay_url,
        room_id=room_response["room_id"],
        relay_token=room_response["relay_token"],
        ttl_seconds=ttl_seconds,
    )
    invite = parse_invite_code(invite_code)
    hello_response = RelayClient(invite.relay_url).post_envelope(
        room_id=invite.room_id,
        relay_token=invite.relay_token,
        envelope=create_pair_hello(room_id=invite.room_id, sender=identity, x25519_public_key=x25519_identity.public_key),
    )
    if hello_response.get("accepted") is not True:
        raise GremlinChatError(f"host pairing hello was rejected by relay: {hello_response}")

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
            "disabled": False,
            "pairing_role": "host",
            "host_hello_posted": True,
            "processed_message_ids": [],
        },
        home,
    )
    _save_latest_invite(home, invite_code=invite_code, room_id=invite.room_id, relay_url=invite.relay_url, expires_at=invite.expires_at)
    append_audit_event(home, {"event_type": "pairing.invite_created", "room_id": invite.room_id, "relay_url": invite.relay_url, "expires_at": invite.expires_at})
    create_receipt(
        home,
        event_type="pairing.invite_created",
        status="created",
        room_id=invite.room_id,
        dedupe_key=f"pairing.invite_created:{invite.room_id}",
        evidence={"room_id": invite.room_id, "relay_url": invite.relay_url, "expires_at": invite.expires_at, "invite_code": invite_code, "host_hello_posted": True},
    )
    return {
        "schema": "gremlinchat.pair-host.v1",
        "created": True,
        "room_id": invite.room_id,
        "relay_url": invite.relay_url,
        "expires_at": invite.expires_at,
        "expires_in_seconds": _expires_in(invite.expires_at),
        "invite_code": invite_code,
        "host_hello_posted": True,
        "relay_locked": bool(hello_response.get("locked", False)),
        "pairing_state": "waiting_for_guest",
        "next_steps": [
            "Share the GC1 invite privately.",
            "After the guest joins, run gremlinchat pair status or gremlinchat room sync.",
            "Compare the safety phrase out of band, then both sides run gremlinchat pair verify --phrase <phrase>.",
        ],
    }


def pair_join(home: Path, code: str, *, read_only_lock: bool = True) -> dict[str, Any]:
    home = ensure_home(home)
    if read_only_lock:
        _ensure_read_only_lock(home)
    if _active_rooms(home):
        raise GremlinChatError("An active pairing room already exists. Revoke, disable, or reset it before joining another invite.")

    identity = load_or_create_identity(home)
    x25519_identity = load_or_create_x25519_identity(home)
    invite = parse_invite_code(code)
    phrase = safety_phrase(invite.pair_secret, [invite.creator_public_key, identity.public_key])
    hello_response = RelayClient(invite.relay_url).post_envelope(
        room_id=invite.room_id,
        relay_token=invite.relay_token,
        envelope=create_pair_hello(room_id=invite.room_id, sender=identity, x25519_public_key=x25519_identity.public_key),
    )
    if hello_response.get("accepted") is not True:
        raise GremlinChatError(f"guest pairing hello was rejected by relay: {hello_response}")

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
            "disabled": False,
            "pairing_role": "guest",
            "processed_message_ids": [],
        },
        home,
    )
    append_audit_event(home, {"event_type": "pairing.invite_accepted", "room_id": invite.room_id, "peer_node_id": invite.creator_node_id, "hello_response": hello_response})
    create_receipt(
        home,
        event_type="pairing.invite_accepted",
        status="joined",
        room_id=invite.room_id,
        dedupe_key=f"pairing.invite_accepted:{invite.room_id}:{invite.creator_node_id}",
        evidence={"room_id": invite.room_id, "peer_node_id": invite.creator_node_id, "hello_response": hello_response, "safety_phrase": phrase},
    )
    return {
        "schema": "gremlinchat.pair-join.v1",
        "joined": True,
        "room_id": invite.room_id,
        "relay_url": invite.relay_url,
        "peer_node_id": invite.creator_node_id,
        "safety_phrase": phrase,
        "hello_posted": True,
        "relay_locked": bool(hello_response.get("locked", False)),
        "pairing_state": "needs_verification",
        "next_steps": [
            "Compare this safety phrase with the host out of band.",
            "Run gremlinchat pair verify --phrase <phrase> only if both sides match.",
            "After both sides verify, use read-only trial commands.",
        ],
    }


def pair_verify(home: Path, *, phrase: str, room_id: str | None = None) -> dict[str, Any]:
    result = verify_room(ensure_home(home), room_id, phrase)
    result["schema"] = "gremlinchat.pair-verify.v1"
    result["pairing_state"] = "verified"
    return result


def pair_status(home: Path, *, include_invite: bool = False) -> dict[str, Any]:
    home = ensure_home(home)
    policy = load_policy(home)
    rooms = [pairing_room_summary(room, policy=policy) for room in load_rooms(home)]
    active = [room for room in rooms if room["pairing_state"] not in {"disabled", "revoked", "expired"}]
    verified = [room for room in active if room["pairing_state"] == "verified"]
    needs_verification = [room for room in active if room["pairing_state"] == "needs_verification"]
    waiting = [room for room in active if room["pairing_state"] == "waiting_for_guest"]
    latest_invite = load_latest_invite(home, include_code=include_invite)
    commands = _pairing_commands(rooms, latest_invite=latest_invite)
    return {
        "schema": "gremlinchat.pair-status.v1",
        "ok": not policy.emergency_stop and not any(room["pairing_state"] == "revoked" for room in rooms),
        "created_at": round(time.time(), 3),
        "room_count": len(rooms),
        "active_room_count": len(active),
        "verified_room_count": len(verified),
        "waiting_room_count": len(waiting),
        "needs_verification_count": len(needs_verification),
        "emergency_stop": policy.emergency_stop,
        "trial_read_only_lock": policy.trial_read_only_lock,
        "latest_invite": latest_invite,
        "rooms": rooms,
        "commands": commands,
        "statement": "Pairing only enables this local owner to send or process runbook requests after the safety phrase is verified locally.",
    }


def pairing_room_summary(room: dict[str, Any], *, policy: Any | None = None) -> dict[str, Any]:
    revoked_node_ids = [] if policy is None else policy.revoked_node_ids
    expires_at = float(room.get("expires_at", 0) or 0)
    peer_node_id = str(room.get("peer_node_id") or "")
    revoked = bool(room.get("revoked_at")) or (peer_node_id and peer_node_id in revoked_node_ids)
    if revoked:
        state = "revoked"
    elif room.get("disabled"):
        state = "disabled"
    elif expires_at and expires_at < time.time() and not room.get("verified"):
        state = "expired"
    elif room.get("verified"):
        state = "verified"
    elif peer_node_id and room.get("safety_phrase"):
        state = "needs_verification"
    else:
        state = "waiting_for_guest"
    return {
        "room_id": room.get("room_id"),
        "relay_url": room.get("relay_url"),
        "pairing_role": room.get("pairing_role") or ("guest" if room.get("joined_by") else "host" if room.get("created_by") else "unknown"),
        "pairing_state": state,
        "peer_node_id": peer_node_id or None,
        "verified": bool(room.get("verified")),
        "disabled": bool(room.get("disabled")),
        "revoked": bool(revoked),
        "safety_phrase": room.get("safety_phrase"),
        "created_at": room.get("created_at"),
        "joined_at": room.get("joined_at"),
        "verified_at": room.get("verified_at"),
        "expires_at": room.get("expires_at"),
        "expires_in_seconds": _expires_in(expires_at) if expires_at else None,
    }


def load_latest_invite(home: Path, *, include_code: bool = False) -> dict[str, Any] | None:
    path = ensure_home(home) / PAIRING_INVITE_FILE
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    expires_at = float(data.get("expires_at", 0) or 0)
    expired = bool(expires_at and expires_at < time.time())
    result = {
        "schema": data.get("schema", "gremlinchat.pairing-latest-invite.v1"),
        "room_id": data.get("room_id"),
        "relay_url": data.get("relay_url"),
        "created_at": data.get("created_at"),
        "expires_at": expires_at,
        "expires_in_seconds": _expires_in(expires_at) if expires_at else None,
        "expired": expired,
        "invite_available": bool(data.get("invite_code_protected")) and not expired,
    }
    if include_code and result["invite_available"]:
        try:
            result["invite_code"] = unprotect_secret(str(data["invite_code_protected"]))
        except Exception:
            result["invite_available"] = False
            result["invite_error"] = "stored invite could not be unprotected"
    return result


def _save_latest_invite(home: Path, *, invite_code: str, room_id: str, relay_url: str, expires_at: float) -> None:
    path = ensure_home(home) / PAIRING_INVITE_FILE
    path.write_text(
        json.dumps(
            {
                "schema": "gremlinchat.pairing-latest-invite.v1",
                "room_id": room_id,
                "relay_url": relay_url,
                "created_at": round(time.time(), 3),
                "expires_at": expires_at,
                "invite_code_protected": protect_secret(invite_code),
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _ensure_read_only_lock(home: Path) -> None:
    policy = load_policy(home)
    if policy.trial_read_only_lock:
        return
    policy.trial_read_only_lock = True
    save_policy(policy, home)
    append_audit_event(home, {"event_type": "pairing.read_only_lock_enabled"})


def _active_rooms(home: Path) -> list[dict[str, Any]]:
    policy = load_policy(home)
    return [room for room in load_rooms(home) if pairing_room_summary(room, policy=policy)["pairing_state"] not in {"disabled", "revoked", "expired"}]


def _pairing_commands(rooms: list[dict[str, Any]], *, latest_invite: dict[str, Any] | None) -> list[str]:
    if not rooms:
        return ["gremlinchat pair host --relay http://YOUR_LAN_OR_TAILSCALE_IP:8778", "gremlinchat pair join GC1:..."]
    first = rooms[0]
    state = first["pairing_state"]
    if state == "waiting_for_guest":
        commands = ["gremlinchat room sync", "gremlinchat pair status"]
        if latest_invite and latest_invite.get("invite_available"):
            commands.insert(0, "Share the latest GC1 invite privately.")
        return commands
    if state == "needs_verification":
        phrase = str(first.get("safety_phrase") or "WORD-WORD-WORD-WORD")
        return ["gremlinchat room sync", f"gremlinchat pair verify --phrase {phrase}"]
    if state == "verified":
        return ["gremlinchat trial listen", "gremlinchat trial prove"]
    return ["gremlinchat trial reset-local --confirm RESET-GREMLINCHAT-TRIAL"]


def _expires_in(expires_at: float) -> int:
    return max(0, int(round(expires_at - time.time())))
