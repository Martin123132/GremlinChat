"""Opaque HTTP relay for GremlinChat envelopes."""

from __future__ import annotations

import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.error import HTTPError
from urllib.parse import parse_qs, quote, urlparse
from urllib.request import Request, urlopen


@dataclass
class RelayRoom:
    room_id: str
    token: str
    expires_at: float
    locked: bool = False
    participants: set[str] = field(default_factory=set)
    messages: list[dict[str, Any]] = field(default_factory=list)


class GremlinRelay:
    def __init__(self):
        self.rooms: dict[str, RelayRoom] = {}

    def create_room(self, *, ttl_seconds: int = 600) -> RelayRoom:
        room = RelayRoom(f"room_{secrets.token_urlsafe(18)}", secrets.token_urlsafe(32), round(time.time() + ttl_seconds, 3))
        self.rooms[room.room_id] = room
        return room

    def get_room(self, room_id: str, token: str) -> RelayRoom:
        room = self.rooms.get(room_id)
        if room is None:
            raise PermissionError("room not found")
        if room.token != token:
            raise PermissionError("relay token rejected")
        if room.expires_at < time.time():
            raise PermissionError("room expired")
        return room

    def append_envelope(self, room_id: str, token: str, envelope: dict[str, Any]) -> dict[str, Any]:
        room = self.get_room(room_id, token)
        sender = str(envelope.get("sender_node_id", ""))
        if not sender:
            raise ValueError("envelope missing sender_node_id")
        if sender not in room.participants:
            if room.locked or len(room.participants) >= 2:
                raise PermissionError("room is locked to its existing participants")
            room.participants.add(sender)
            if len(room.participants) == 2:
                room.locked = True
        index = len(room.messages)
        room.messages.append({"index": index, "received_at": round(time.time(), 3), "envelope": envelope})
        return {"accepted": True, "index": index, "locked": room.locked}

    def messages_after(self, room_id: str, token: str, after: int = -1) -> dict[str, Any]:
        room = self.get_room(room_id, token)
        return {
            "room_id": room.room_id,
            "locked": room.locked,
            "participants": sorted(room.participants),
            "messages": [message for message in room.messages if int(message["index"]) > after],
        }


def create_relay_http_server(relay: GremlinRelay | None = None, host: str = "127.0.0.1", port: int = 8778) -> ThreadingHTTPServer:
    relay = GremlinRelay() if relay is None else relay
    lock = threading.Lock()

    class RelayHandler(BaseHTTPRequestHandler):
        server_version = "GremlinChatRelay/0.1"

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            try:
                if parsed.path == "/v1/rooms":
                    request = _read_json(self)
                    with lock:
                        room = relay.create_room(ttl_seconds=int(request.get("ttl_seconds", 600)))
                    _json_response(self, 201, {"room_id": room.room_id, "relay_token": room.token, "expires_at": room.expires_at})
                    return
                parts = [part for part in parsed.path.split("/") if part]
                if len(parts) == 4 and parts[:2] == ["v1", "rooms"] and parts[3] == "messages":
                    request = _read_json(self)
                    with lock:
                        response = relay.append_envelope(parts[2], str(request.get("relay_token", "")), request["envelope"])
                    _json_response(self, 201, response)
                    return
                _json_response(self, 404, {"error": "not found"})
            except PermissionError as exc:
                _json_response(self, 403, {"accepted": False, "error": str(exc)})
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                _json_response(self, 400, {"accepted": False, "error": str(exc)})

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/health":
                _json_response(self, 200, {"ok": True, "rooms": len(relay.rooms)})
                return
            parts = [part for part in parsed.path.split("/") if part]
            if len(parts) == 4 and parts[:2] == ["v1", "rooms"] and parts[3] == "messages":
                query = parse_qs(parsed.query)
                try:
                    with lock:
                        response = relay.messages_after(parts[2], query.get("token", [""])[0], int(query.get("after", ["-1"])[0]))
                    _json_response(self, 200, response)
                except PermissionError as exc:
                    _json_response(self, 403, {"error": str(exc)})
                return
            _json_response(self, 404, {"error": "not found"})

        def log_message(self, format: str, *args: Any) -> None:
            return

    return ThreadingHTTPServer((host, port), RelayHandler)


class RelayClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(f"{self.base_url}{path}", data=body, method=method, headers={"Content-Type": "application/json"})
        try:
            with urlopen(request, timeout=10) as response:
                raw = response.read()
        except HTTPError as exc:
            raw = exc.read()
            data = json.loads(raw.decode("utf-8")) if raw else {"error": str(exc)}
            data["http_status"] = exc.code
            return data
        return json.loads(raw.decode("utf-8")) if raw else {}

    def create_room(self, *, ttl_seconds: int = 600) -> dict[str, Any]:
        return self._request("POST", "/v1/rooms", {"ttl_seconds": ttl_seconds})

    def post_envelope(self, *, room_id: str, relay_token: str, envelope: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", f"/v1/rooms/{room_id}/messages", {"relay_token": relay_token, "envelope": envelope})

    def messages_after(self, *, room_id: str, relay_token: str, after: int = -1) -> dict[str, Any]:
        return self._request("GET", f"/v1/rooms/{room_id}/messages?token={quote(relay_token)}&after={after}")


def _read_json(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    content_length = int(handler.headers.get("Content-Length", "0"))
    if content_length == 0:
        return {}
    return json.loads(handler.rfile.read(content_length).decode("utf-8"))


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)

