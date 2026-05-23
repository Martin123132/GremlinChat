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
gremlinchat relay serve --host 0.0.0.0 --port 8778
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
