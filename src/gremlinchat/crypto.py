"""Identity, invite, and encrypted envelope primitives."""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import secrets
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .jsonutil import canonical_bytes

INVITE_PREFIX = "GC1:"
DEFAULT_INVITE_TTL_SECONDS = 600


def b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + ("=" * (-len(data) % 4)))


@dataclass(frozen=True)
class NodeIdentity:
    node_id: str
    public_key: str
    private_key: str | None = None

    @classmethod
    def generate(cls, prefix: str = "gremlin") -> "NodeIdentity":
        private = ed25519.Ed25519PrivateKey.generate()
        public = private.public_key()
        public_bytes = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        private_bytes = private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        fingerprint = hashlib.sha256(public_bytes).hexdigest()[:16]
        return cls(f"{prefix}_{fingerprint}", b64encode(public_bytes), b64encode(private_bytes))

    def public(self) -> "NodeIdentity":
        return NodeIdentity(node_id=self.node_id, public_key=self.public_key)

    def sign(self, payload: bytes) -> str:
        if self.private_key is None:
            raise ValueError("Private key is required for signing")
        private = ed25519.Ed25519PrivateKey.from_private_bytes(b64decode(self.private_key))
        return b64encode(private.sign(payload))

    def verify(self, payload: bytes, signature: str) -> bool:
        public = ed25519.Ed25519PublicKey.from_public_bytes(b64decode(self.public_key))
        try:
            public.verify(b64decode(signature), payload)
            return True
        except InvalidSignature:
            return False


@dataclass(frozen=True)
class X25519Identity:
    private_key: str
    public_key: str

    @classmethod
    def generate(cls) -> "X25519Identity":
        private = x25519.X25519PrivateKey.generate()
        public = private.public_key()
        return cls(
            private_key=b64encode(
                private.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                )
            ),
            public_key=b64encode(public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
        )


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def protect_secret(secret_text: str) -> str:
    raw = secret_text.encode("utf-8")
    if sys.platform == "win32":
        return "dpapi:" + b64encode(_crypt_protect_data(raw))
    return "plain:" + b64encode(raw)


def unprotect_secret(protected_text: str) -> str:
    if protected_text.startswith("dpapi:"):
        return _crypt_unprotect_data(b64decode(protected_text.removeprefix("dpapi:"))).decode("utf-8")
    if protected_text.startswith("plain:"):
        return b64decode(protected_text.removeprefix("plain:")).decode("utf-8")
    raise ValueError("Unsupported GremlinChat secret protection format")


def _bytes_from_blob(blob: _DataBlob) -> bytes:
    return ctypes.string_at(blob.pbData, blob.cbData)


def _crypt_protect_data(data: bytes) -> bytes:
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    in_buffer = ctypes.create_string_buffer(data)
    in_blob = _DataBlob(len(data), ctypes.cast(in_buffer, ctypes.POINTER(ctypes.c_ubyte)))
    out_blob = _DataBlob()
    if not crypt32.CryptProtectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
        raise OSError("CryptProtectData failed")
    try:
        return _bytes_from_blob(out_blob)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def _crypt_unprotect_data(data: bytes) -> bytes:
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    in_buffer = ctypes.create_string_buffer(data)
    in_blob = _DataBlob(len(data), ctypes.cast(in_buffer, ctypes.POINTER(ctypes.c_ubyte)))
    out_blob = _DataBlob()
    if not crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
        raise OSError("CryptUnprotectData failed")
    try:
        return _bytes_from_blob(out_blob)
    finally:
        kernel32.LocalFree(out_blob.pbData)


@dataclass(frozen=True)
class Invite:
    relay_url: str
    room_id: str
    relay_token: str
    creator_node_id: str
    creator_public_key: str
    creator_x25519_public_key: str
    pair_secret: str
    expires_at: float
    checksum: str


def create_invite_code(
    *,
    creator: NodeIdentity,
    creator_x25519_public_key: str,
    relay_url: str,
    room_id: str | None = None,
    relay_token: str | None = None,
    ttl_seconds: int = DEFAULT_INVITE_TTL_SECONDS,
) -> str:
    payload = {
        "v": 1,
        "relay_url": relay_url.rstrip("/"),
        "room_id": room_id or f"room_{secrets.token_urlsafe(18)}",
        "relay_token": relay_token or secrets.token_urlsafe(32),
        "creator_node_id": creator.node_id,
        "creator_public_key": creator.public_key,
        "creator_x25519_public_key": creator_x25519_public_key,
        "pair_secret": b64encode(secrets.token_bytes(32)),
        "expires_at": round(time.time() + ttl_seconds, 3),
    }
    payload["checksum"] = _checksum(payload)
    return INVITE_PREFIX + b64encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def parse_invite_code(code: str, *, now: float | None = None, require_fresh: bool = True) -> Invite:
    if not code.startswith(INVITE_PREFIX):
        raise ValueError("GremlinChat invite codes must start with GC1:")
    try:
        payload = json.loads(b64decode(code.removeprefix(INVITE_PREFIX)).decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise ValueError("GremlinChat invite code could not be decoded") from exc
    required = {
        "v",
        "relay_url",
        "room_id",
        "relay_token",
        "creator_node_id",
        "creator_public_key",
        "creator_x25519_public_key",
        "pair_secret",
        "expires_at",
        "checksum",
    }
    missing = sorted(required - set(payload))
    if missing:
        raise ValueError(f"GremlinChat invite code is missing fields: {', '.join(missing)}")
    expected = _checksum({key: value for key, value in payload.items() if key != "checksum"})
    if not secrets.compare_digest(str(payload["checksum"]), expected):
        raise ValueError("GremlinChat invite checksum mismatch")
    timestamp = time.time() if now is None else now
    if require_fresh and float(payload["expires_at"]) < timestamp:
        raise ValueError("GremlinChat invite code has expired")
    return Invite(
        relay_url=str(payload["relay_url"]).rstrip("/"),
        room_id=str(payload["room_id"]),
        relay_token=str(payload["relay_token"]),
        creator_node_id=str(payload["creator_node_id"]),
        creator_public_key=str(payload["creator_public_key"]),
        creator_x25519_public_key=str(payload["creator_x25519_public_key"]),
        pair_secret=str(payload["pair_secret"]),
        expires_at=float(payload["expires_at"]),
        checksum=str(payload["checksum"]),
    )


def _checksum(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()[:16]


def derive_room_key(
    *,
    local_private_key: str,
    peer_public_key: str,
    pair_secret: str,
    participant_public_keys: list[str],
) -> bytes:
    private = x25519.X25519PrivateKey.from_private_bytes(b64decode(local_private_key))
    peer_public = x25519.X25519PublicKey.from_public_bytes(b64decode(peer_public_key))
    shared = private.exchange(peer_public)
    info = canonical_bytes({"protocol": "gremlinchat.room-key.v1", "participants": sorted(participant_public_keys)})
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b64decode(pair_secret), info=info).derive(shared)


def safety_phrase(pair_secret: str, participant_public_keys: list[str]) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(canonical_bytes({"pair_secret": pair_secret, "participants": sorted(participant_public_keys)}))
    raw = digest.finalize()
    words = [
        "amber",
        "brisk",
        "cobalt",
        "delta",
        "ember",
        "frost",
        "harbor",
        "ivory",
        "juniper",
        "keystone",
        "lantern",
        "meadow",
        "north",
        "onyx",
        "prairie",
        "quartz",
    ]
    return "-".join(words[byte % len(words)] for byte in raw[:4])


@dataclass(frozen=True)
class EncryptedEnvelope:
    protocol: str
    room_id: str
    message_id: str
    created_at: float
    sender_node_id: str
    sender_public_key: str
    nonce: str
    ciphertext: str
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "room_id": self.room_id,
            "message_id": self.message_id,
            "created_at": self.created_at,
            "sender_node_id": self.sender_node_id,
            "sender_public_key": self.sender_public_key,
            "nonce": self.nonce,
            "ciphertext": self.ciphertext,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EncryptedEnvelope":
        return cls(**data)

    def unsigned_dict(self) -> dict[str, Any]:
        data = self.to_dict()
        data.pop("signature")
        return data


class ReplayGuard:
    def __init__(self, seen_message_ids: set[str] | None = None):
        self.seen_message_ids = set() if seen_message_ids is None else set(seen_message_ids)

    def accept_once(self, message_id: str) -> None:
        if message_id in self.seen_message_ids:
            raise ValueError(f"replayed GremlinChat message rejected: {message_id}")
        self.seen_message_ids.add(message_id)


def seal_message(
    *,
    room_id: str,
    sender: NodeIdentity,
    room_key: bytes,
    message: dict[str, Any],
) -> EncryptedEnvelope:
    nonce = os.urandom(12)
    message_id = f"msg_{uuid.uuid4().hex}"
    created_at = round(time.time(), 3)
    aad = canonical_bytes(
        {
            "protocol": "gremlinchat.envelope.v1",
            "room_id": room_id,
            "message_id": message_id,
            "created_at": created_at,
            "sender_node_id": sender.node_id,
            "sender_public_key": sender.public_key,
        }
    )
    ciphertext = AESGCM(room_key).encrypt(nonce, canonical_bytes(message), aad)
    unsigned = {
        "protocol": "gremlinchat.envelope.v1",
        "room_id": room_id,
        "message_id": message_id,
        "created_at": created_at,
        "sender_node_id": sender.node_id,
        "sender_public_key": sender.public_key,
        "nonce": b64encode(nonce),
        "ciphertext": b64encode(ciphertext),
    }
    return EncryptedEnvelope(**unsigned, signature=sender.sign(canonical_bytes(unsigned)))


def open_message(
    *,
    envelope: EncryptedEnvelope,
    room_key: bytes,
    replay_guard: ReplayGuard | None = None,
) -> dict[str, Any]:
    if envelope.protocol != "gremlinchat.envelope.v1":
        raise ValueError("Unsupported GremlinChat envelope protocol")
    signer = NodeIdentity(node_id=envelope.sender_node_id, public_key=envelope.sender_public_key)
    if not signer.verify(canonical_bytes(envelope.unsigned_dict()), envelope.signature):
        raise ValueError("GremlinChat envelope signature rejected")
    if replay_guard is not None:
        replay_guard.accept_once(envelope.message_id)
    aad = canonical_bytes(
        {
            "protocol": envelope.protocol,
            "room_id": envelope.room_id,
            "message_id": envelope.message_id,
            "created_at": envelope.created_at,
            "sender_node_id": envelope.sender_node_id,
            "sender_public_key": envelope.sender_public_key,
        }
    )
    try:
        plaintext = AESGCM(room_key).decrypt(b64decode(envelope.nonce), b64decode(envelope.ciphertext), aad)
    except InvalidTag as exc:
        raise ValueError("GremlinChat envelope decryption failed") from exc
    return json.loads(plaintext.decode("utf-8"))

