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
```

Run a local relay:

```powershell
gremlinchat relay serve --host 127.0.0.1 --port 8778 --state-dir "$env:LOCALAPPDATA\GremlinChat\relay"
```

Create a room:

```powershell
gremlinchat room create --relay http://RELAY_HOST:8778
```

Join from the other machine:

```powershell
gremlinchat room join GC1:...
gremlinchat room verify --phrase WORD-WORD-WORD-WORD
gremlinchat room loop
```

Request a safe proof:

```powershell
gremlinchat room sync
gremlinchat room verify --phrase WORD-WORD-WORD-WORD
gremlinchat room request --runbook presence.ping
gremlinchat room sync
```

## Private Read-Only Trial

For the first Martin/Glyn trial, use a private LAN or Tailscale IP for the relay. Avoid public relay exposure. If you bind the relay to `0.0.0.0`, GremlinChat prints a warning because every network interface is listening.

Host relay on one trusted machine:

```powershell
gremlinchat relay serve --host YOUR_LAN_OR_TAILSCALE_IP --port 8778 --state-dir "$env:LOCALAPPDATA\GremlinChat\relay"
```

Check readiness:

```powershell
gremlinchat trial preflight --relay http://YOUR_LAN_OR_TAILSCALE_IP:8778 --write-report
```

Host creates the private invite:

```powershell
gremlinchat trial host --relay http://YOUR_LAN_OR_TAILSCALE_IP:8778
```

Guest joins with the invite code shared privately:

```powershell
gremlinchat trial guest GC1:...
```

Both sides compare the safety phrase by phone or another trusted channel, then each runs:

```powershell
gremlinchat room verify --phrase WORD-WORD-WORD-WORD
```

Guest keeps their machine listening for read-only proof requests:

```powershell
gremlinchat room loop
```

Host runs the read-only proof and writes a redacted report:

```powershell
gremlinchat trial prove
```

Run a one-machine proof before involving another person:

```powershell
gremlinchat trial simulate
```

Write a redacted local trial report:

```powershell
gremlinchat trial report
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

Rooms cannot send or process encrypted runbook requests until the local owner runs `room verify` with the exact safety phrase shown by both machines.

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

## Windows Install Script

From a checked-out repo:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install_gremlinchat_windows.ps1
```
