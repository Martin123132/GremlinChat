"""Local GremlinChat dashboard."""

from __future__ import annotations

import html
import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlparse

from .pairing import pair_host, pair_join, pair_status, pair_verify
from .receipts import compare_receipts, create_receipt, receipt_status, write_receipt_bundle
from .roomops import GremlinChatError, disable_room, process_room_once, request_runbook, revoke_room, sync_room_messages
from .runbooks import runbook_catalog
from .store import decide_approval, load_approvals, load_or_create_dashboard_token, load_or_create_identity, load_policy, load_rooms, read_audit_events, save_policy
from .trial import RESET_CONFIRMATION, build_trial_checklist, reset_local_trial, trial_status, write_trial_bundle


def create_daemon_http_server(home: Path, host: str = "127.0.0.1", port: int = 8777) -> ThreadingHTTPServer:
    home = Path(home)
    lock = threading.Lock()

    class DaemonHandler(BaseHTTPRequestHandler):
        server_version = "GremlinChatDaemon/0.1"

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path in {"/", "/dashboard"}:
                with lock:
                    _html_response(self, 200, _render_dashboard(_snapshot(home, include_csrf=True)))
                return
            if parsed.path == "/api/status":
                with lock:
                    _json_response(self, 200, _snapshot(home))
                return
            if parsed.path == "/api/trial/status":
                query = parse_qs(parsed.query)
                with lock:
                    _json_response(self, 200, trial_status(home, relay_url=query.get("relay", [None])[0]))
                return
            if parsed.path == "/api/pair/status":
                with lock:
                    _json_response(self, 200, pair_status(home))
                return
            if parsed.path == "/api/trial/checklist":
                query = parse_qs(parsed.query)
                role = query.get("role", ["host"])[0]
                try:
                    with lock:
                        _json_response(self, 200, build_trial_checklist(home, role=role, relay_url=query.get("relay", [None])[0]))
                except GremlinChatError as exc:
                    _json_response(self, 400, {"ok": False, "error": str(exc)})
                return
            if parsed.path == "/api/receipts/status":
                with lock:
                    _json_response(self, 200, receipt_status(home))
                return
            if parsed.path == "/api/receipts/compare":
                query = parse_qs(parsed.query)
                with lock:
                    _json_response(self, 200, compare_receipts(home, room_id=query.get("room_id", [None])[0]))
                return
            _json_response(self, 404, {"error": "not found"})

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            if not _csrf_valid(home, parsed):
                _json_response(self, 403, {"ok": False, "error": "dashboard CSRF token rejected"})
                return
            if parsed.path == "/api/emergency-stop":
                with lock:
                    policy = load_policy(home)
                    policy.emergency_stop = True
                    save_policy(policy, home)
                    create_receipt(home, event_type="emergency-stop", status="active", evidence={"emergency_stop": True, "trigger": "dashboard", "event_at": time.time()})
                    _action_response(self, parsed, {"ok": True, "emergency_stop": True})
                return
            if parsed.path == "/api/receipts/bundle":
                query = parse_qs(parsed.query)
                with lock:
                    _action_response(self, parsed, {"ok": True, "bundle_paths": write_receipt_bundle(home, room_id=query.get("room_id", [None])[0])})
                return
            if parsed.path == "/api/pair/host":
                values = _request_values(self, parsed)
                relay = values.get("relay", [""])[0] or "http://127.0.0.1:8778"
                ttl_seconds = int(values.get("ttl_seconds", ["600"])[0] or "600")
                try:
                    with lock:
                        _action_response(self, parsed, {"ok": True, "pairing": pair_host(home, relay_url=relay, ttl_seconds=ttl_seconds)})
                except GremlinChatError as exc:
                    _json_response(self, 400, {"ok": False, "error": str(exc)})
                return
            if parsed.path == "/api/pair/join":
                values = _request_values(self, parsed)
                code = values.get("code", [""])[0]
                try:
                    with lock:
                        _action_response(self, parsed, {"ok": True, "pairing": pair_join(home, code)})
                except (GremlinChatError, ValueError) as exc:
                    _json_response(self, 400, {"ok": False, "error": str(exc)})
                return
            if parsed.path == "/api/pair/verify":
                values = _request_values(self, parsed)
                room_id = values.get("room_id", [""])[0] or None
                phrase = values.get("phrase", [""])[0]
                try:
                    with lock:
                        _action_response(self, parsed, {"ok": True, "pairing": pair_verify(home, room_id=room_id, phrase=phrase)})
                except GremlinChatError as exc:
                    _json_response(self, 400, {"ok": False, "error": str(exc)})
                return
            if parsed.path == "/api/trial/bundle":
                query = parse_qs(parsed.query)
                with lock:
                    _action_response(self, parsed, {"ok": True, "bundle_paths": write_trial_bundle(home, relay_url=query.get("relay", [None])[0])})
                return
            if parsed.path == "/api/trial/reset-local":
                query = parse_qs(parsed.query)
                confirm = query.get("confirm", [""])[0]
                try:
                    with lock:
                        _action_response(self, parsed, {"ok": True, "reset": reset_local_trial(home, confirm=confirm)})
                except GremlinChatError as exc:
                    _json_response(self, 400, {"ok": False, "error": str(exc), "required_confirm": RESET_CONFIRMATION})
                return
            if parsed.path in {"/api/rooms/sync", "/api/rooms/request", "/api/rooms/disable", "/api/rooms/revoke"}:
                room_id = parse_qs(parsed.query).get("room_id", [""])[0] or None
                try:
                    with lock:
                        if parsed.path == "/api/rooms/sync":
                            payload = {"ok": True, "sync": sync_room_messages(home, room_id)}
                            try:
                                payload["process"] = process_room_once(home, room_id)
                            except GremlinChatError as exc:
                                payload["process_error"] = str(exc)
                        elif parsed.path == "/api/rooms/request":
                            runbook = parse_qs(parsed.query).get("runbook", [""])[0]
                            if runbook not in {"presence.ping", "gremlinchat.doctor"}:
                                _json_response(self, 400, {"ok": False, "error": "dashboard only sends read-only ping and doctor requests"})
                                return
                            payload = {"ok": True, "request": request_runbook(home, room_id, runbook, {})}
                        elif parsed.path == "/api/rooms/disable":
                            payload = {"ok": True, "disable": disable_room(home, room_id)}
                        else:
                            payload = {"ok": True, "revoke": revoke_room(home, room_id)}
                    _action_response(self, parsed, payload)
                except GremlinChatError as exc:
                    _json_response(self, 400, {"ok": False, "error": str(exc)})
                return
            if parsed.path in {"/api/approvals/approve", "/api/approvals/reject"}:
                approval_id = parse_qs(parsed.query).get("approval_id", [""])[0]
                if not approval_id:
                    _json_response(self, 400, {"ok": False, "error": "approval_id is required"})
                    return
                try:
                    approval = decide_approval(home, approval_id, approved=parsed.path.endswith("/approve"))
                except KeyError as exc:
                    _json_response(self, 404, {"ok": False, "error": str(exc)})
                    return
                _action_response(self, parsed, {"ok": True, "approval": approval})
                return
            _json_response(self, 404, {"error": "not found"})

        def log_message(self, format: str, *args: Any) -> None:
            return

    return ThreadingHTTPServer((host, port), DaemonHandler)


def _snapshot(home: Path, *, include_csrf: bool = False) -> dict[str, Any]:
    identity = load_or_create_identity(home)
    policy = load_policy(home)
    snapshot = {
        "product": "GremlinChat",
        "node_id": identity.node_id,
        "home": str(home),
        "rooms": [_room_summary(room) for room in load_rooms(home)],
        "policy": runbook_catalog(policy),
        "approvals": load_approvals(home),
        "audit": read_audit_events(home, limit=25),
        "pairing": pair_status(home, include_invite=include_csrf),
        "trial": trial_status(home),
        "receipts": receipt_status(home),
    }
    if include_csrf:
        snapshot["csrf_token"] = load_or_create_dashboard_token(home)
    return snapshot


def _room_summary(room: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in room.items()
        if key not in {"relay_token", "relay_token_protected", "pair_secret", "pair_secret_protected"}
    }


def _render_dashboard(snapshot: dict[str, Any]) -> str:
    node_id = html.escape(snapshot["node_id"])
    home = html.escape(snapshot["home"])
    csrf = quote(str(snapshot.get("csrf_token", "")), safe="")
    policy = snapshot["policy"]
    pairing = snapshot["pairing"]
    pending = [approval for approval in snapshot["approvals"] if approval.get("status") == "pending"]
    room_rows = "\n".join(_room_row(room, csrf) for room in snapshot["rooms"]) or "<tr><td colspan=\"6\" class=\"empty\">No paired rooms yet.</td></tr>"
    pairing_panel = _pairing_panel(pairing, csrf)
    trial = snapshot["trial"]
    trial_rows = _trial_rows(trial)
    receipt_rows = _receipt_rows(snapshot["receipts"])
    receipt_compare_rows = _receipt_compare_rows(snapshot["receipts"].get("compare", {}))
    approval_rows = "\n".join(
        f"<tr><td><code>{html.escape(str(approval.get('approval_id', '')))}</code></td><td>{html.escape(str(approval.get('runbook', '')))}</td><td>{html.escape(str(approval.get('reason', '')))}</td><td><form method=\"post\" action=\"/api/approvals/approve?approval_id={quote(str(approval.get('approval_id', '')), safe='')}&redirect=1&csrf={csrf}\"><button>Approve</button></form><form method=\"post\" action=\"/api/approvals/reject?approval_id={quote(str(approval.get('approval_id', '')), safe='')}&redirect=1&csrf={csrf}\"><button>Reject</button></form></td></tr>"
        for approval in pending
    ) or "<tr><td colspan=\"4\" class=\"empty\">No pending approvals.</td></tr>"
    audit_rows = "\n".join(
        f"<tr><td>{html.escape(str(event.get('created_at', '')))}</td><td>{html.escape(str(event.get('event_type', '')))}</td><td>{html.escape(str(event.get('runbook', '')))}</td><td>{html.escape(str(event.get('summary', '')))}</td></tr>"
        for event in reversed(snapshot["audit"])
    ) or "<tr><td colspan=\"4\" class=\"empty\">No audit events yet.</td></tr>"
    emergency = "ON" if policy["emergency_stop"] else "OFF"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="8">
  <title>GremlinChat</title>
  <style>
    :root {{ --bg:#f7f7f4; --surface:#fff; --text:#20231f; --muted:#626960; --line:#deded6; --green:#24734d; --red:#a13d35; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; background:var(--bg); color:var(--text); font-family:Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; font-size:14px; }}
    header {{ padding:24px 28px 18px; background:var(--surface); border-bottom:1px solid var(--line); }}
    h1,h2 {{ margin:0; letter-spacing:0; }} h1 {{ font-size:26px; }} h2 {{ font-size:16px; }}
    main {{ width:min(1280px, 100%); margin:0 auto; padding:20px 24px 34px; }}
    .subhead {{ margin-top:6px; color:var(--muted); overflow-wrap:anywhere; }}
    .metrics {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:12px; margin-bottom:16px; }}
    .metric, section {{ padding:16px; border:1px solid var(--line); border-radius:8px; background:var(--surface); }}
    section {{ margin-top:16px; overflow-x:auto; }}
    .metric span {{ display:block; color:var(--muted); font-size:12px; text-transform:uppercase; }}
    .metric strong {{ display:block; margin-top:8px; font-size:22px; overflow-wrap:anywhere; }}
    table {{ width:100%; border-collapse:collapse; table-layout:fixed; margin-top:10px; }}
    th,td {{ padding:10px 8px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; overflow-wrap:anywhere; }}
    th {{ color:var(--muted); font-size:12px; text-transform:uppercase; }}
    code {{ font-family:Consolas, "Liberation Mono", monospace; font-size:12px; }}
    .state {{ display:inline-block; min-width:72px; padding:4px 8px; border-radius:999px; background:{'#a13d35' if policy['emergency_stop'] else '#24734d'}; color:#fff; text-align:center; font-size:12px; }}
    .empty {{ color:var(--muted); }}
    input, textarea {{ width:100%; min-width:180px; padding:7px 9px; border:1px solid var(--line); border-radius:6px; font:inherit; }}
    textarea {{ min-height:76px; font-family:Consolas, "Liberation Mono", monospace; font-size:12px; resize:vertical; }}
    button {{ margin:2px 0; padding:6px 10px; border:1px solid var(--line); border-radius:6px; background:#fff; cursor:pointer; }}
    .actions {{ display:flex; flex-wrap:wrap; gap:8px; align-items:center; margin-top:12px; }}
    .actions a {{ display:inline-block; padding:6px 10px; border:1px solid var(--line); border-radius:6px; color:var(--text); text-decoration:none; background:#fff; }}
    .pair-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:12px; margin-top:12px; }}
    .pair-grid form {{ display:grid; gap:8px; }}
    .hint {{ color:var(--muted); font-size:12px; margin-top:6px; }}
  </style>
</head>
<body>
  <header><h1>GremlinChat</h1><div class="subhead">Local control room for <code>{node_id}</code>. Home: <code>{home}</code>.</div></header>
  <main>
    <div class="metrics">
      <div class="metric"><span>Emergency Stop</span><strong><span class="state">{html.escape(emergency)}</span></strong><form method="post" action="/api/emergency-stop?redirect=1&csrf={csrf}"><button>Emergency Stop</button></form></div>
      <div class="metric"><span>Rooms</span><strong>{len(snapshot["rooms"])}</strong></div>
      <div class="metric"><span>Trust Receipts</span><strong>{snapshot["receipts"].get("count", 0)}</strong></div>
      <div class="metric"><span>Pending Approvals</span><strong>{len(pending)}</strong></div>
      <div class="metric"><span>Write Runbooks</span><strong>{len(policy["enabled_write_runbooks"])}</strong></div>
    </div>
    <section><h2>Pairing Ceremony</h2>{pairing_panel}</section>
    <section><h2>Trial</h2><table><thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead><tbody>{trial_rows}</tbody></table><div class="actions"><a href="/api/trial/checklist?role=host">Checklist</a><form method="post" action="/api/trial/bundle?redirect=1&csrf={csrf}"><button>Bundle</button></form><form method="post" action="/api/emergency-stop?redirect=1&csrf={csrf}"><button>Emergency Stop</button></form></div></section>
    <section><h2>Trust Receipts</h2><table><thead><tr><th>Receipt</th><th>Source</th><th>Issuer</th><th>Event</th><th>Status</th></tr></thead><tbody>{receipt_rows}</tbody></table><div class="actions"><a href="/api/receipts/status">Status</a><a href="/api/receipts/compare">Compare</a><form method="post" action="/api/receipts/bundle?redirect=1&csrf={csrf}"><button>Bundle</button></form></div><table><thead><tr><th>Comparison</th><th>Count</th><th>Meaning</th></tr></thead><tbody>{receipt_compare_rows}</tbody></table></section>
    <section><h2>Rooms</h2><table><thead><tr><th>Room</th><th>Relay</th><th>Partner</th><th>State</th><th>Safety Phrase</th><th>Actions</th></tr></thead><tbody>{room_rows}</tbody></table></section>
    <section><h2>Pending Approvals</h2><table><thead><tr><th>Approval</th><th>Runbook</th><th>Reason</th><th>Decision</th></tr></thead><tbody>{approval_rows}</tbody></table></section>
    <section><h2>Audit</h2><table><thead><tr><th>Time</th><th>Event</th><th>Runbook</th><th>Summary</th></tr></thead><tbody>{audit_rows}</tbody></table></section>
  </main>
</body>
</html>"""


def _pairing_panel(pairing: dict[str, Any], csrf: str) -> str:
    latest = pairing.get("latest_invite") or {}
    invite_code = str(latest.get("invite_code") or "")
    invite_html = ""
    if invite_code:
        invite_html = (
            "<div>"
            "<label>Latest private invite</label>"
            f"<textarea readonly>{html.escape(invite_code)}</textarea>"
            f"<div class=\"hint\">Expires in {html.escape(str(latest.get('expires_in_seconds', 0)))} seconds. Share privately only.</div>"
            "</div>"
        )
    rooms = pairing.get("rooms", [])
    state_rows = "\n".join(
        f"<tr><td><code>{html.escape(str(room.get('room_id', '')))}</code></td>"
        f"<td>{html.escape(str(room.get('pairing_role', '')))}</td>"
        f"<td><code>{html.escape(str(room.get('pairing_state', '')))}</code></td>"
        f"<td>{html.escape(str(room.get('safety_phrase') or 'not ready'))}</td></tr>"
        for room in rooms
    ) or "<tr><td colspan=\"4\" class=\"empty\">No pairing rooms yet.</td></tr>"
    return f"""
      <div class="pair-grid">
        <form method="post" action="/api/pair/host?redirect=1&csrf={csrf}">
          <strong>Host</strong>
          <input name="relay" value="http://127.0.0.1:8778" aria-label="Relay URL">
          <input name="ttl_seconds" value="600" aria-label="Invite expiry seconds">
          <button>Create Invite</button>
        </form>
        <form method="post" action="/api/pair/join?redirect=1&csrf={csrf}">
          <strong>Join</strong>
          <input name="code" placeholder="GC1:..." aria-label="Invite code">
          <button>Join Invite</button>
        </form>
        {invite_html}
      </div>
      <table><thead><tr><th>Room</th><th>Role</th><th>State</th><th>Safety Phrase</th></tr></thead><tbody>{state_rows}</tbody></table>
      <div class="actions"><a href="/api/pair/status">Pair Status</a><a href="/api/trial/checklist?role=host">Host Checklist</a><a href="/api/trial/checklist?role=guest">Guest Checklist</a></div>
    """


def _trial_rows(trial: dict[str, Any]) -> str:
    latest = trial.get("latest_proof") or {}
    rows = [
        ("Preflight", "pass" if trial.get("ok") else "check", "No failed preflight checks." if trial.get("ok") else "One or more preflight checks need attention."),
        ("Verified Rooms", str(trial.get("verified_room_count", 0)), f"{trial.get('room_count', 0)} total rooms"),
        ("Read-Only Lock", "on" if trial.get("trial_read_only_lock") else "off", "Write-capable runbooks are blocked." if trial.get("trial_read_only_lock") else "Turn this on before a live trial."),
        ("Emergency Stop", "on" if trial.get("emergency_stop") else "off", "Remote processing is disabled." if trial.get("emergency_stop") else "Remote read-only processing is allowed after verification."),
        ("Latest Proof", str(latest.get("ok", "none")), str(latest.get("summary", "No proof report found."))),
    ]
    return "\n".join(
        f"<tr><td>{html.escape(name)}</td><td><code>{html.escape(status)}</code></td><td>{html.escape(detail)}</td></tr>"
        for name, status, detail in rows
    )


def _receipt_rows(receipts: dict[str, Any]) -> str:
    rows = [("local", item) for item in receipts.get("latest", [])] + [("partner", item) for item in receipts.get("partner_latest", [])]
    if not rows:
        return "<tr><td colspan=\"5\" class=\"empty\">No Trust Receipts yet.</td></tr>"
    return "\n".join(
        f"<tr><td><code>{html.escape(str(receipt.get('receipt_id', '')))}</code></td>"
        f"<td>{html.escape(source)}</td>"
        f"<td><code>{html.escape(str(receipt.get('issuer_node_id', '')))}</code></td>"
        f"<td>{html.escape(str(receipt.get('event_type', '')))}</td>"
        f"<td><code>{html.escape(str(receipt.get('status', '')))}</code></td></tr>"
        for source, receipt in rows
    )


def _receipt_compare_rows(compare: dict[str, Any]) -> str:
    rows = [
        ("Matched", compare.get("matched_count", 0), "Local and imported partner evidence line up."),
        ("Missing", compare.get("missing_count", 0), "Expected partner/local evidence has not been imported yet."),
        ("Mismatches", compare.get("mismatch_count", 0), "Imported evidence disagrees with local evidence."),
    ]
    return "\n".join(
        f"<tr><td>{html.escape(name)}</td><td><code>{html.escape(str(count))}</code></td><td>{html.escape(meaning)}</td></tr>"
        for name, count, meaning in rows
    )


def _room_row(room: dict[str, Any], csrf: str) -> str:
    room_id = str(room.get("room_id", ""))
    room_id_q = quote(room_id, safe="")
    actions = " ".join(
        [
            f"<form method=\"post\" action=\"/api/rooms/sync?room_id={room_id_q}&redirect=1&csrf={csrf}\"><button>Sync</button></form>",
            f"<form method=\"post\" action=\"/api/pair/verify?room_id={room_id_q}&redirect=1&csrf={csrf}\"><input name=\"phrase\" placeholder=\"Safety phrase\"><button>Verify</button></form>",
            f"<form method=\"post\" action=\"/api/rooms/request?room_id={room_id_q}&runbook=presence.ping&redirect=1&csrf={csrf}\"><button>Ping</button></form>",
            f"<form method=\"post\" action=\"/api/rooms/request?room_id={room_id_q}&runbook=gremlinchat.doctor&redirect=1&csrf={csrf}\"><button>Doctor</button></form>",
            f"<form method=\"post\" action=\"/api/rooms/disable?room_id={room_id_q}&redirect=1&csrf={csrf}\"><button>Disable</button></form>",
            f"<form method=\"post\" action=\"/api/rooms/revoke?room_id={room_id_q}&redirect=1&csrf={csrf}\"><button>Revoke</button></form>",
        ]
    )
    return (
        f"<tr><td><code>{html.escape(room_id)}</code></td>"
        f"<td>{html.escape(str(room.get('relay_url', '')))}</td>"
        f"<td><code>{html.escape(str(room.get('peer_node_id', 'pending')))}</code></td>"
        f"<td>{html.escape(_room_state(room))}</td>"
        f"<td>{html.escape(str(room.get('safety_phrase', 'not ready')))}</td>"
        f"<td>{actions}</td></tr>"
    )


def _room_state(room: dict[str, Any]) -> str:
    if room.get("disabled"):
        return "disabled"
    if room.get("verified"):
        return "verified"
    return "not verified"


def _html_response(handler: BaseHTTPRequestHandler, status: int, markup: str) -> None:
    body = markup.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _csrf_valid(home: Path, parsed: Any) -> bool:
    supplied = parse_qs(parsed.query).get("csrf", [""])[0]
    expected = load_or_create_dashboard_token(home)
    return bool(supplied) and secrets.compare_digest(supplied, expected)


def _request_values(handler: BaseHTTPRequestHandler, parsed: Any) -> dict[str, list[str]]:
    values = {key: list(value) for key, value in parse_qs(parsed.query).items()}
    content_length = int(handler.headers.get("Content-Length", "0") or "0")
    if content_length <= 0:
        return values
    raw = handler.rfile.read(content_length)
    if not raw:
        return values
    content_type = handler.headers.get("Content-Type", "")
    if "application/json" in content_type:
        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            payload = {}
        for key, value in payload.items():
            values.setdefault(str(key), []).append(str(value))
        return values
    for key, value in parse_qs(raw.decode("utf-8")).items():
        values.setdefault(key, []).extend(value)
    return values


def _action_response(handler: BaseHTTPRequestHandler, parsed: Any, payload: dict[str, Any]) -> None:
    if parse_qs(parsed.query).get("redirect", ["0"])[0] == "1":
        handler.send_response(303)
        handler.send_header("Location", "/dashboard")
        handler.send_header("Content-Length", "0")
        handler.end_headers()
        return
    _json_response(handler, 200, payload)
