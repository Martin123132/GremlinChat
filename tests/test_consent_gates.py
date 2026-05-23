from argparse import Namespace

import pytest

from gremlinchat.cli import _process_room_once, disable_room, verify_room
from gremlinchat.crypto import NodeIdentity, X25519Identity
from gremlinchat.store import load_rooms, save_room


def _room(peer=None, peer_x=None):
    peer = NodeIdentity.generate() if peer is None else peer
    peer_x = X25519Identity.generate() if peer_x is None else peer_x
    return {
        "room_id": "room_consent",
        "relay_url": "http://127.0.0.1:9",
        "relay_token": "test-token",
        "pair_secret": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "peer_node_id": peer.node_id,
        "peer_public_key": peer.public_key,
        "peer_x25519_public_key": peer_x.public_key,
        "safety_phrase": "amber-brisk-cobalt-delta",
        "verified": False,
        "disabled": False,
        "processed_message_ids": [],
    }


def test_room_process_requires_local_verification(tmp_path):
    save_room(_room(), tmp_path)

    with pytest.raises(SystemExit, match="not verified"):
        _process_room_once(tmp_path, "room_consent")


def test_room_verify_requires_exact_safety_phrase(tmp_path):
    save_room(_room(), tmp_path)

    with pytest.raises(SystemExit, match="mismatch"):
        verify_room(Namespace(home=str(tmp_path), room_id="room_consent", phrase="wrong-phrase"))

    verify_room(Namespace(home=str(tmp_path), room_id="room_consent", phrase="amber-brisk-cobalt-delta"))
    room = load_rooms(tmp_path)[0]
    assert room["verified"] is True
    assert room["disabled"] is False
    assert "verified_at" in room


def test_room_disable_blocks_processing_until_reverified(tmp_path):
    room = _room()
    room["verified"] = True
    save_room(room, tmp_path)

    disable_room(Namespace(home=str(tmp_path), room_id="room_consent"))
    disabled = load_rooms(tmp_path)[0]
    assert disabled["verified"] is False
    assert disabled["disabled"] is True

    with pytest.raises(SystemExit, match="disabled"):
        _process_room_once(tmp_path, "room_consent")

