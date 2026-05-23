"""Signed pairing hello packets and encrypted task message helpers."""

from __future__ import annotations

import time
import uuid
from typing import Any

from .crypto import NodeIdentity
from .jsonutil import canonical_bytes


def create_pair_hello(*, room_id: str, sender: NodeIdentity, x25519_public_key: str) -> dict[str, Any]:
    unsigned = {
        "protocol": "gremlinchat.pair-hello.v1",
        "room_id": room_id,
        "hello_id": f"hello_{uuid.uuid4().hex}",
        "sender_node_id": sender.node_id,
        "sender_public_key": sender.public_key,
        "x25519_public_key": x25519_public_key,
        "created_at": round(time.time(), 3),
    }
    return {**unsigned, "signature": sender.sign(canonical_bytes(unsigned))}


def verify_pair_hello(hello: dict[str, Any]) -> bool:
    if hello.get("protocol") != "gremlinchat.pair-hello.v1":
        return False
    unsigned = dict(hello)
    signature = str(unsigned.pop("signature", ""))
    sender = NodeIdentity(str(hello.get("sender_node_id", "")), str(hello.get("sender_public_key", "")))
    return sender.verify(canonical_bytes(unsigned), signature)


def create_task_request(*, runbook: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "type": "task.request.v1",
        "task_id": f"task_{uuid.uuid4().hex}",
        "created_at": round(time.time(), 3),
        "runbook": runbook,
        "payload": {} if payload is None else payload,
    }


def create_task_result(*, request: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "task.result.v1",
        "task_id": request["task_id"],
        "created_at": round(time.time(), 3),
        "runbook": request["runbook"],
        "result": result,
    }

