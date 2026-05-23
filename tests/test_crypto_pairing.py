import json

import pytest

from gremlinchat.crypto import (
    NodeIdentity,
    ReplayGuard,
    X25519Identity,
    b64decode,
    b64encode,
    create_invite_code,
    derive_room_key,
    open_message,
    parse_invite_code,
    safety_phrase,
    seal_message,
)


def test_invite_codes_validate_checksum_and_expiry():
    creator = NodeIdentity.generate()
    x25519 = X25519Identity.generate()
    code = create_invite_code(
        creator=creator,
        creator_x25519_public_key=x25519.public_key,
        relay_url="http://relay.example",
        ttl_seconds=60,
    )
    invite = parse_invite_code(code)

    assert invite.creator_node_id == creator.node_id
    assert invite.creator_x25519_public_key == x25519.public_key

    payload = json.loads(b64decode(code.removeprefix("GC1:")).decode("utf-8"))
    payload["relay_url"] = "http://changed.example"
    tampered = "GC1:" + b64encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    with pytest.raises(ValueError, match="checksum"):
        parse_invite_code(tampered)

    expired = create_invite_code(
        creator=creator,
        creator_x25519_public_key=x25519.public_key,
        relay_url="http://relay.example",
        ttl_seconds=-1,
    )
    with pytest.raises(ValueError, match="expired"):
        parse_invite_code(expired)


def test_encrypted_envelope_hides_payload_and_rejects_replay():
    alice = NodeIdentity.generate()
    bob = NodeIdentity.generate()
    alice_x = X25519Identity.generate()
    bob_x = X25519Identity.generate()
    code = create_invite_code(
        creator=alice,
        creator_x25519_public_key=alice_x.public_key,
        relay_url="http://relay.example",
    )
    invite = parse_invite_code(code)
    participants = [alice.public_key, bob.public_key]
    alice_key = derive_room_key(
        local_private_key=alice_x.private_key,
        peer_public_key=bob_x.public_key,
        pair_secret=invite.pair_secret,
        participant_public_keys=participants,
    )
    bob_key = derive_room_key(
        local_private_key=bob_x.private_key,
        peer_public_key=alice_x.public_key,
        pair_secret=invite.pair_secret,
        participant_public_keys=participants,
    )

    assert alice_key == bob_key
    assert safety_phrase(invite.pair_secret, participants) == safety_phrase(invite.pair_secret, list(reversed(participants)))

    message = {"type": "task.request.v1", "runbook": "repo.status", "payload": {"repo_path": "C:/private/repo"}}
    envelope = seal_message(room_id=invite.room_id, sender=alice, room_key=alice_key, message=message)
    relay_visible = json.dumps(envelope.to_dict())
    assert "repo.status" not in relay_visible
    assert "C:/private/repo" not in relay_visible

    guard = ReplayGuard()
    assert open_message(envelope=envelope, room_key=bob_key, replay_guard=guard) == message
    with pytest.raises(ValueError, match="replayed"):
        open_message(envelope=envelope, room_key=bob_key, replay_guard=guard)

