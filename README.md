# GremlinChat

Private, permissioned machine-to-machine coordination for people using local AI/coding agents.

GremlinChat is not remote desktop and it is not arbitrary remote shell. It gives two people a shared control room where their machines can exchange encrypted runbook requests, owner approvals, redacted results, and Codex-friendly reports.

## Public Repo Rule

This repository contains product code only. Do not commit:

- real invite codes
- relay tokens
- IP addresses or private hostnames
- partner names, customer names, or private workflow notes
- machine-specific runbook policy
- logs containing secrets

Exchange private connection details by phone, email, or a future private repo.

## Quickstart

```powershell
python -m pip install -e ".[dev]"
gremlinchat setup
gremlinchat install doctor --write-report
```

Run a local relay:

```powershell
gremlinchat relay serve --host 127.0.0.1 --port 8778 --state-dir "$env:LOCALAPPDATA\GremlinChat\relay"
```

Create a first-run pairing invite. The host command immediately posts the host's signed pairing hello to the relay, so the room can lock to the host plus one guest:

```powershell
gremlinchat pair host --relay http://RELAY_HOST:8778
```

Join from the other machine:

```powershell
gremlinchat pair join GC1:...
gremlinchat pair status
gremlinchat pair verify --phrase WORD-WORD-WORD-WORD
gremlinchat trial listen
```

Request a safe proof:

```powershell
gremlinchat room sync
gremlinchat pair verify --phrase WORD-WORD-WORD-WORD
gremlinchat room request --runbook presence.ping
gremlinchat room sync
```

## Private Read-Only Trial

For the first Martin/Glyn trial, use a private LAN or Tailscale IP for the relay. Avoid public relay exposure. If you bind the relay to `0.0.0.0`, GremlinChat prints a warning because every network interface is listening.

Host relay on one trusted machine:

```powershell
gremlinchat relay serve --host YOUR_LAN_OR_TAILSCALE_IP --port 8778 --state-dir "$env:LOCALAPPDATA\GremlinChat\relay"
```

The relay is deliberately small and capped: it rejects oversized request bodies, oversized encrypted envelopes, and rooms that exceed the configured message limit. The defaults are intended for status/proof traffic, not file transfer.

Check readiness:

```powershell
gremlinchat install doctor --write-report
gremlinchat trial preflight --relay http://YOUR_LAN_OR_TAILSCALE_IP:8778 --write-report
```

Show role-specific next steps at any point:

```powershell
gremlinchat trial checklist --role host --relay http://YOUR_LAN_OR_TAILSCALE_IP:8778
gremlinchat trial checklist --role guest
```

Host starts a guided session. This runs preflight, keeps the read-only lock on, and creates one invite only if there is no active local room:

```powershell
gremlinchat trial host-session --relay http://YOUR_LAN_OR_TAILSCALE_IP:8778
```

Guest starts a guided session with the invite code shared privately. This runs preflight, keeps the read-only lock on, and refuses to join a second room if one already exists:

```powershell
gremlinchat trial guest-session GC1:...
```

The lower-level `trial host` and `trial guest` commands are still available for debugging, but `host-session` and `guest-session` are the recommended first live-trial path.

Both sides compare the safety phrase by phone or another trusted channel, then each runs:

```powershell
gremlinchat pair verify --phrase WORD-WORD-WORD-WORD
```

At any point, either side can inspect the consent state without exposing the invite code:

```powershell
gremlinchat pair status
```

Guest keeps their machine listening for read-only proof requests:

```powershell
gremlinchat trial listen
```

Host runs the read-only proof and writes a redacted report:

```powershell
gremlinchat trial prove
```

`trial listen` exists for the first trial because it always enforces the read-only trial lock before processing partner requests. Use `room loop` only when you deliberately want the lower-level room processor.

Run a one-machine proof before involving another person:

```powershell
gremlinchat trial simulate
```

Write a redacted local trial report:

```powershell
gremlinchat trial report
```

Write a redacted support bundle for debugging without pasting a huge terminal dump:

```powershell
gremlinchat trial bundle --relay http://YOUR_LAN_OR_TAILSCALE_IP:8778
```

List signed Trust Receipts created by pairing, task requests/results, proof runs, revoke, and emergency stop:

```powershell
gremlinchat receipt list
gremlinchat receipt show receipt_...
gremlinchat receipt verify "$env:LOCALAPPDATA\GremlinChat\receipts\receipt_....json"
gremlinchat receipt verify-bundle "$env:LOCALAPPDATA\GremlinChat\reports\receipt-bundle-....json"
gremlinchat receipt import "$env:USERPROFILE\Downloads\glyn-receipt-bundle.json"
gremlinchat receipt compare --room-id room_...
gremlinchat receipt bundle
```

Trust Receipts prove that a local GremlinChat node signed a redacted event record and that the file has not been altered. They do not prove that the signing node is trusted; you still compare the pairing safety phrase out of band.

Clear local trial rooms, approvals, and reports for a fresh attempt while preserving this machine's identity and revoked peers:

```powershell
gremlinchat trial reset-local --confirm RESET-GREMLINCHAT-TRIAL
```

Revoke a paired room immediately:

```powershell
gremlinchat room revoke
```

Open the local dashboard:

```powershell
gremlinchat daemon serve
```

Dashboard URL:

```text
http://127.0.0.1:8777/dashboard
```

Dashboard buttons use a local CSRF token, so state-changing dashboard requests must come from the dashboard page itself.

The dashboard includes a Pairing Ceremony section for creating a private invite, joining an invite, syncing, entering the verified safety phrase, revoking, and triggering emergency stop. The normal `/api/pair/status` endpoint does not return the invite code; the dashboard page can show the latest unexpired local invite because it is rendered with the local CSRF-protected dashboard session.

## Runbooks

Read-only runbooks can run automatically:

- `presence.ping`
- `machine.status`
- `repo.status`
- `worker.status`
- `gremlinchat.doctor`

Write-capable runbooks require owner configuration or approval:

- `repo.pull_ff_only`
- `worker.restart_named`
- `tests.run_allowlisted`

For the private read-only trial, GremlinChat keeps `trial_read_only_lock` on by default. That blocks write-capable runbooks even if an older local policy accidentally enabled them.

Use this to stop all remote requests immediately:

```powershell
gremlinchat emergency-stop
```

Disable one room without deleting it:

```powershell
gremlinchat room disable
```

Rooms cannot send or process encrypted runbook requests until the local owner runs `pair verify` or `room verify` with the exact safety phrase shown by both machines.

Pending approvals:

```powershell
gremlinchat approval list
gremlinchat approval approve approval_...
gremlinchat approval reject approval_...
```

Reports are written under:

```text
%LOCALAPPDATA%\GremlinChat\reports\
```

Trust Receipts are written under:

```text
%LOCALAPPDATA%\GremlinChat\receipts\
```

Imported partner receipts are written under:

```text
%LOCALAPPDATA%\GremlinChat\partner-receipts\
```

The latest locally generated invite is stored temporarily under local GremlinChat state using local secret protection so the dashboard can display it until it expires. Invite codes, relay tokens, local reports, and partner receipts must still stay out of git.

## Windows Install Script

From a checked-out repo:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install_gremlinchat_windows.ps1
```

The installer creates Start Menu shortcuts for Dashboard, Trial Listener, Preflight, Install Doctor, and Emergency Stop, then runs:

```powershell
gremlinchat install doctor --write-report
```
