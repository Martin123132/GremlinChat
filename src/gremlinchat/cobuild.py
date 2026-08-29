"""Co-build project aliases, diagnostics, and Codex handoff packets."""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.11+ is required.
    tomllib = None  # type: ignore[assignment]

from .redaction import redact_value
from .store import append_audit_event, ensure_home, read_audit_events

PROJECTS_SCHEMA = "gremlinchat.cobuild-projects.v1"
HANDOFF_SCHEMA = "gremlinchat.cobuild-handoff.v1"
COBUILD_READ_RUNBOOKS = {"project.status", "project.structure", "project.errors", "project.deps", "project.bundle"}

ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
DEFAULT_DIAGNOSTIC_FILES = [
    "GREMLINCHAT_ERRORS.md",
    "GREMLINCHAT_DIAGNOSTICS.md",
    ".gremlinchat/errors.txt",
    ".gremlinchat/diagnostics.md",
]
IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".next",
    ".nuxt",
    "dist",
    "build",
    "target",
    "coverage",
}
SENSITIVE_NAME_PARTS = (
    ".env",
    "secret",
    "token",
    "password",
    "passwd",
    "credential",
    "private",
    "id_rsa",
    ".pem",
    ".pfx",
    ".p12",
)
DEPENDENCY_FILES = (
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "requirements-dev.txt",
    "requirements.in",
    "Pipfile",
)


def add_project_card(
    home: Path,
    *,
    alias: str,
    path: str | Path,
    description: str = "",
    diagnostic_files: list[str] | None = None,
) -> dict[str, Any]:
    home = ensure_home(home)
    alias = _validate_alias(alias)
    root = Path(path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError(f"Project path does not exist or is not a directory: {root}")
    files = _normalise_diagnostic_files(diagnostic_files)
    cards = [card for card in load_project_cards(home) if card.get("alias") != alias]
    card = {
        "schema": "gremlinchat.cobuild-project.v1",
        "alias": alias,
        "path": str(root),
        "description": str(description or ""),
        "diagnostic_files": files,
        "created_at": round(time.time(), 3),
        "updated_at": round(time.time(), 3),
    }
    cards.append(card)
    _write_project_cards(home, cards)
    append_audit_event(home, {"event_type": "cobuild.project_saved", "project": alias, "path": str(root)})
    return {"ok": True, "project": _project_summary(card, include_path=True)}


def remove_project_card(home: Path, *, alias: str) -> dict[str, Any]:
    home = ensure_home(home)
    alias = _validate_alias(alias)
    cards = load_project_cards(home)
    kept = [card for card in cards if card.get("alias") != alias]
    if len(kept) == len(cards):
        raise KeyError(f"Unknown co-build project alias: {alias}")
    _write_project_cards(home, kept)
    append_audit_event(home, {"event_type": "cobuild.project_removed", "project": alias})
    return {"ok": True, "removed": alias}


def load_project_cards(home: Path) -> list[dict[str, Any]]:
    path = ensure_home(home) / "cobuild-projects.json"
    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    return [dict(item) for item in payload.get("projects", [])]


def project_card(home: Path, alias: str) -> dict[str, Any]:
    alias = _validate_alias(alias)
    for card in load_project_cards(home):
        if card.get("alias") == alias:
            return card
    raise PermissionError(f"Project alias {alias!r} is not registered on this machine.")


def cobuild_status(home: Path, *, limit: int = 20) -> dict[str, Any]:
    home = ensure_home(home)
    reports = _recent_project_reports(home, limit=limit)
    timeline = _timeline(home, reports, limit=limit)
    return {
        "schema": "gremlinchat.cobuild-status.v1",
        "project_count": len(load_project_cards(home)),
        "projects": [_project_summary(card, include_path=True) for card in load_project_cards(home)],
        "read_runbooks": sorted(COBUILD_READ_RUNBOOKS),
        "recent_reports": [_report_summary(report) for report in reports],
        "timeline": timeline,
        "statement": "Co-Build Mode uses local project aliases and read-only diagnostics only; partners never receive arbitrary shell access.",
    }


def run_project_runbook(home: Path | None, runbook: str, payload: dict[str, Any] | None) -> dict[str, Any]:
    if home is None:
        raise PermissionError("Project diagnostics require a configured GremlinChat home.")
    if runbook not in COBUILD_READ_RUNBOOKS:
        raise PermissionError(f"Unknown co-build runbook: {runbook}")
    payload = {} if payload is None else payload
    alias = str(payload.get("project") or payload.get("project_alias") or "").strip()
    if not alias:
        raise PermissionError("Project diagnostics require a local project alias.")
    card = project_card(home, alias)
    root = Path(str(card["path"])).expanduser().resolve()
    question = _bounded_text(str(payload.get("question") or payload.get("request") or ""), 1200)

    if runbook == "project.status":
        return project_status(card, root, question=question)
    if runbook == "project.structure":
        return project_structure(card, root, question=question)
    if runbook == "project.errors":
        return project_errors(card, root, question=question)
    if runbook == "project.deps":
        return project_deps(card, root, question=question)
    if runbook == "project.bundle":
        status = project_status(card, root, question=question)
        structure = project_structure(card, root, question=question)
        deps = project_deps(card, root, question=question)
        errors = project_errors(card, root, question=question)
        bundle = {
            "schema": "gremlinchat.project-bundle.v1",
            "summary": f"Co-build bundle collected for project alias {card['alias']}.",
            "project": _project_summary(card, include_path=False),
            "question": question,
            "status": status,
            "structure": structure,
            "dependencies": deps,
            "errors": errors,
            "codex_handoff": _codex_handoff_text(card["alias"], question, status=status, structure=structure, deps=deps, errors=errors),
        }
        return sanitize_cobuild_value(home, bundle)
    raise PermissionError(f"Unknown co-build runbook: {runbook}")


def project_status(card: dict[str, Any], root: Path, *, question: str = "") -> dict[str, Any]:
    git = _git_summary(root)
    detected = _detected_files(root)
    return sanitize_cobuild_value(
        root,
        {
            "schema": "gremlinchat.project-status.v1",
            "summary": f"Project status collected for alias {card['alias']}.",
            "project": _project_summary(card, include_path=False),
            "question": question,
            "root_name": root.name,
            "exists": root.exists(),
            "is_git_repo": git["is_git_repo"],
            "git": git,
            "detected_files": detected,
            "detected_stack": _detected_stack(detected),
            "checked_at": round(time.time(), 3),
        },
    )


def project_structure(card: dict[str, Any], root: Path, *, question: str = "", max_entries: int = 160, max_depth: int = 4) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    omitted = {"ignored_dirs": 0, "sensitive_names": 0, "limit": 0}
    if root.exists():
        for current, dirnames, filenames in os.walk(root):
            current_path = Path(current)
            rel = current_path.relative_to(root)
            depth = 0 if str(rel) == "." else len(rel.parts)
            dirnames[:] = sorted(dirnames)
            filenames = sorted(filenames)
            filtered_dirs = []
            for dirname in dirnames:
                if dirname in IGNORED_DIRS:
                    omitted["ignored_dirs"] += 1
                    continue
                if _sensitive_name(dirname):
                    omitted["sensitive_names"] += 1
                    continue
                filtered_dirs.append(dirname)
            dirnames[:] = filtered_dirs if depth < max_depth else []

            for dirname in dirnames:
                if len(entries) >= max_entries:
                    omitted["limit"] += 1
                    continue
                entries.append({"type": "dir", "path": _safe_relative((current_path / dirname).relative_to(root))})
            for filename in filenames:
                if _sensitive_name(filename):
                    omitted["sensitive_names"] += 1
                    continue
                if len(entries) >= max_entries:
                    omitted["limit"] += 1
                    continue
                entries.append({"type": "file", "path": _safe_relative((current_path / filename).relative_to(root))})
    return {
        "schema": "gremlinchat.project-structure.v1",
        "summary": f"Project structure collected for alias {card['alias']}.",
        "project": _project_summary(card, include_path=False),
        "question": question,
        "max_entries": max_entries,
        "max_depth": max_depth,
        "entries": entries,
        "omitted": omitted,
    }


def project_errors(card: dict[str, Any], root: Path, *, question: str = "") -> dict[str, Any]:
    diagnostics = []
    omitted = []
    for rel in card.get("diagnostic_files") or DEFAULT_DIAGNOSTIC_FILES:
        try:
            path = _safe_project_path(root, rel)
        except ValueError:
            omitted.append({"file": str(rel), "reason": "path escaped project"})
            continue
        if not path.exists() or not path.is_file():
            continue
        if _sensitive_path(path.relative_to(root)):
            omitted.append({"file": _safe_relative(path.relative_to(root)), "reason": "sensitive file name"})
            continue
        text = _read_text_tail(path, limit=6000)
        diagnostics.append({"file": _safe_relative(path.relative_to(root)), "chars": len(text), "content": sanitize_cobuild_value(root, text)})
    return {
        "schema": "gremlinchat.project-errors.v1",
        "summary": f"Diagnostic notes collected for alias {card['alias']}." if diagnostics else f"No GremlinChat diagnostic notes found for alias {card['alias']}.",
        "project": _project_summary(card, include_path=False),
        "question": question,
        "diagnostic_files_checked": list(card.get("diagnostic_files") or DEFAULT_DIAGNOSTIC_FILES),
        "diagnostics": diagnostics,
        "omitted": omitted,
        "note": "Only owner-configured GremlinChat diagnostic files are read; raw project logs are not scraped automatically.",
    }


def project_deps(card: dict[str, Any], root: Path, *, question: str = "") -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    for filename in DEPENDENCY_FILES:
        path = root / filename
        if path.exists() and path.is_file():
            files.append(_dependency_file_summary(root, path))
    for path in sorted(root.glob("*.csproj"))[:20]:
        files.append(_csproj_summary(root, path))
    return sanitize_cobuild_value(
        root,
        {
            "schema": "gremlinchat.project-deps.v1",
            "summary": f"Dependency summary collected for alias {card['alias']}.",
            "project": _project_summary(card, include_path=False),
            "question": question,
            "files": files,
            "file_count": len(files),
        },
    )


def write_cobuild_handoff_packet(home: Path, *, room_id: str | None = None, task_id: str | None = None, question: str | None = None) -> dict[str, str]:
    home = ensure_home(home)
    reports = _recent_project_reports(home, limit=1000)
    if room_id:
        reports = [report for report in reports if report.get("room_id") == room_id or report.get("result", {}).get("room_id") == room_id]
    if task_id:
        reports = [report for report in reports if report.get("task_id") == task_id or report.get("result", {}).get("task_id") == task_id]
    if not reports:
        raise FileNotFoundError("No co-build project result reports were found.")
    report = reports[0]
    runbook = str(report.get("runbook") or report.get("result", {}).get("runbook") or "")
    result = dict(report.get("result") or {})
    output = dict(result.get("output") or {})
    packet = sanitize_cobuild_value(
        home,
        {
            "schema": HANDOFF_SCHEMA,
            "created_at": round(time.time(), 3),
            "room_id": room_id,
            "task_id": report.get("task_id") or result.get("task_id"),
            "runbook": runbook,
            "question": question or output.get("question") or "",
            "result_summary": result.get("summary"),
            "result_status": result.get("status"),
            "accepted": result.get("accepted"),
            "evidence": output,
            "prompt": _handoff_prompt(runbook, result, output, question=question),
        },
    )
    reports_dir = home / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    suffix = uuid.uuid4().hex[:8]
    json_path = reports_dir / f"cobuild-handoff-{stamp}-{suffix}.json"
    md_path = reports_dir / f"cobuild-handoff-{stamp}-{suffix}.md"
    json_path.write_text(json.dumps(packet, indent=2, sort_keys=True), encoding="utf-8")
    md_path.write_text(_handoff_markdown(packet), encoding="utf-8")
    append_audit_event(home, {"event_type": "cobuild.handoff_written", "task_id": packet.get("task_id"), "runbook": runbook, "json": str(json_path), "markdown": str(md_path)})
    try:
        from .receipts import create_receipt

        create_receipt(
            home,
            event_type="cobuild.handoff",
            status="written",
            room_id=room_id,
            task_id=str(packet.get("task_id") or ""),
            runbook=runbook,
            dedupe_key=f"cobuild.handoff:{packet.get('task_id')}:{stamp}:{suffix}",
            evidence={"packet": packet},
        )
    except Exception:
        pass
    return {"json": str(json_path), "markdown": str(md_path)}


def sanitize_cobuild_value(home_or_root: Path, value: Any) -> Any:
    base_text = str(home_or_root).replace("\\", "/")
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, nested in value.items():
            key_lower = str(key).lower()
            if key_lower in {"path", "repo_path", "cwd", "home", "executable"} or key_lower.endswith("_path"):
                result[key] = _redact_paths(base_text, nested)
            elif key_lower in {"stdout", "stderr", "raw_log", "raw_logs", "log"}:
                result[key] = _bounded_text(str(redact_value(_redact_paths(base_text, nested))), 4000)
            else:
                result[key] = sanitize_cobuild_value(home_or_root, nested)
        return redact_value(result)
    if isinstance(value, list):
        return [sanitize_cobuild_value(home_or_root, item) for item in value]
    if isinstance(value, str):
        return redact_value(_redact_paths(base_text, value))
    return value


def _write_project_cards(home: Path, cards: list[dict[str, Any]]) -> None:
    (home / "cobuild-projects.json").write_text(
        json.dumps({"schema": PROJECTS_SCHEMA, "projects": cards}, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def _validate_alias(alias: str) -> str:
    alias = str(alias or "").strip()
    if not ALIAS_RE.match(alias):
        raise ValueError("Project alias must be 1-64 characters using letters, numbers, dot, dash, or underscore.")
    return alias


def _normalise_diagnostic_files(files: list[str] | None) -> list[str]:
    result = list(DEFAULT_DIAGNOSTIC_FILES if not files else files)
    clean = []
    for item in result:
        text = str(item).replace("\\", "/").strip().lstrip("/")
        if not text or ".." in Path(text).parts:
            raise ValueError("Diagnostic files must be relative paths inside the project.")
        clean.append(text)
    return clean


def _project_summary(card: dict[str, Any], *, include_path: bool) -> dict[str, Any]:
    root = Path(str(card.get("path", "")))
    summary = {
        "alias": card.get("alias"),
        "description": card.get("description", ""),
        "root_name": root.name,
        "exists": root.exists(),
        "diagnostic_files": list(card.get("diagnostic_files") or DEFAULT_DIAGNOSTIC_FILES),
        "updated_at": card.get("updated_at"),
    }
    if include_path:
        summary["path"] = str(root)
    else:
        summary["path"] = "[local-only]"
    return summary


def _git_summary(root: Path) -> dict[str, Any]:
    inside = _run(["git", "rev-parse", "--is-inside-work-tree"], cwd=root, timeout_seconds=8)
    if inside["returncode"] != 0:
        return {"is_git_repo": False, "branch": None, "commit": None, "clean": None, "status": []}
    branch = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=root, timeout_seconds=8)
    commit = _run(["git", "rev-parse", "HEAD"], cwd=root, timeout_seconds=8)
    status = _run(["git", "status", "--short", "--branch"], cwd=root, timeout_seconds=12)
    porcelain = _run(["git", "status", "--porcelain"], cwd=root, timeout_seconds=12)
    return {
        "is_git_repo": True,
        "branch": _bounded_text(branch["stdout"].strip(), 200),
        "commit": _bounded_text(commit["stdout"].strip(), 80),
        "clean": not bool(porcelain["stdout"].strip()),
        "status": [_bounded_text(line, 300) for line in status["stdout"].splitlines()[:80]],
    }


def _run(command: list[str], *, cwd: Path, timeout_seconds: int) -> dict[str, Any]:
    try:
        completed = subprocess.run(command, cwd=str(cwd), check=False, capture_output=True, text=True, timeout=timeout_seconds)
        return {
            "returncode": completed.returncode,
            "stdout": _bounded_text(completed.stdout, 6000),
            "stderr": _bounded_text(completed.stderr, 2000),
        }
    except Exception as exc:
        return {"returncode": 1, "stdout": "", "stderr": str(exc)}


def _detected_files(root: Path) -> list[str]:
    names = [
        "package.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "package-lock.json",
        "pyproject.toml",
        "requirements.txt",
        "poetry.lock",
        "uv.lock",
        "Pipfile",
        "Cargo.toml",
        "go.mod",
        "composer.json",
        "Dockerfile",
        "docker-compose.yml",
        "README.md",
    ]
    found = [name for name in names if (root / name).exists()]
    if list(root.glob("*.sln")):
        found.append("*.sln")
    if list(root.glob("*.csproj")):
        found.append("*.csproj")
    return found


def _detected_stack(files: list[str]) -> list[str]:
    stack = []
    if any(item in files for item in ["package.json", "pnpm-lock.yaml", "yarn.lock", "package-lock.json"]):
        stack.append("node")
    if any(item in files for item in ["pyproject.toml", "requirements.txt", "poetry.lock", "uv.lock", "Pipfile"]):
        stack.append("python")
    if "*.csproj" in files or "*.sln" in files:
        stack.append("dotnet")
    if "Cargo.toml" in files:
        stack.append("rust")
    if "go.mod" in files:
        stack.append("go")
    if "Dockerfile" in files or "docker-compose.yml" in files:
        stack.append("docker")
    return stack


def _dependency_file_summary(root: Path, path: Path) -> dict[str, Any]:
    rel = _safe_relative(path.relative_to(root))
    if path.name == "package.json":
        return {"file": rel, "kind": "node", "data": _package_json_deps(path)}
    if path.name == "pyproject.toml":
        return {"file": rel, "kind": "python", "data": _pyproject_deps(path)}
    if path.name.startswith("requirements"):
        return {"file": rel, "kind": "python", "data": {"requirements": _requirements_lines(path)}}
    if path.name == "Pipfile":
        return {"file": rel, "kind": "python", "data": {"present": True, "note": "Pipfile detected; contents not expanded in v0.1."}}
    return {"file": rel, "kind": "unknown", "data": {"present": True}}


def _package_json_deps(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(_read_text_head(path, limit=512_000))
    except Exception as exc:
        return {"error": str(exc)}
    return {
        "name": payload.get("name"),
        "version": payload.get("version"),
        "dependencies": _limited_mapping(payload.get("dependencies", {})),
        "devDependencies": _limited_mapping(payload.get("devDependencies", {})),
        "optionalDependencies": _limited_mapping(payload.get("optionalDependencies", {})),
        "script_names": sorted((payload.get("scripts") or {}).keys())[:80],
    }


def _pyproject_deps(path: Path) -> dict[str, Any]:
    if tomllib is None:
        return {"error": "tomllib is unavailable"}
    try:
        payload = tomllib.loads(_read_text_head(path, limit=512_000))
    except Exception as exc:
        return {"error": str(exc)}
    project = payload.get("project") or {}
    tool = payload.get("tool") or {}
    poetry = (tool.get("poetry") or {}) if isinstance(tool, dict) else {}
    return {
        "name": project.get("name") or poetry.get("name"),
        "requires_python": project.get("requires-python"),
        "dependencies": list(project.get("dependencies") or [])[:120],
        "optional_dependency_groups": sorted((project.get("optional-dependencies") or {}).keys())[:80],
        "poetry_dependencies": sorted((poetry.get("dependencies") or {}).keys())[:120] if isinstance(poetry, dict) else [],
        "build_backend": (payload.get("build-system") or {}).get("build-backend"),
    }


def _requirements_lines(path: Path) -> list[str]:
    lines = []
    for line in _read_text_head(path, limit=256_000).splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "://" in stripped or stripped.startswith(("-e ", "--extra-index-url", "--index-url")):
            lines.append("[redacted-private-requirement]")
        else:
            lines.append(_bounded_text(str(redact_value(stripped)), 240))
        if len(lines) >= 120:
            break
    return lines


def _csproj_summary(root: Path, path: Path) -> dict[str, Any]:
    rel = _safe_relative(path.relative_to(root))
    try:
        tree = ET.fromstring(_read_text_head(path, limit=512_000))
    except Exception as exc:
        return {"file": rel, "kind": "dotnet", "data": {"error": str(exc)}}
    packages = []
    target_frameworks = []
    for element in tree.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        if tag in {"TargetFramework", "TargetFrameworks"} and element.text:
            target_frameworks.extend(part.strip() for part in element.text.split(";") if part.strip())
        if tag == "PackageReference":
            packages.append({"include": element.attrib.get("Include"), "version": element.attrib.get("Version")})
    return {"file": rel, "kind": "dotnet", "data": {"target_frameworks": target_frameworks[:20], "package_references": packages[:120]}}


def _limited_mapping(value: Any, *, limit: int = 120) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {str(key): redact_value(value[key]) for key in sorted(value)[:limit]}


def _recent_project_reports(home: Path, *, limit: int) -> list[dict[str, Any]]:
    reports_dir = ensure_home(home) / "reports"
    if not reports_dir.exists():
        return []
    rows = []
    for path in sorted(reports_dir.glob("task_*.json"), key=lambda item: item.stat().st_mtime, reverse=True):
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        runbook = str(report.get("runbook") or report.get("result", {}).get("runbook") or "")
        if runbook in COBUILD_READ_RUNBOOKS:
            report["_path"] = str(path)
            rows.append(report)
        if len(rows) >= limit:
            break
    return rows


def _report_summary(report: dict[str, Any]) -> dict[str, Any]:
    result = report.get("result") or {}
    return {
        "task_id": report.get("task_id") or result.get("task_id"),
        "runbook": report.get("runbook") or result.get("runbook"),
        "status": result.get("status"),
        "accepted": result.get("accepted"),
        "summary": result.get("summary"),
        "path": report.get("_path", "[local-report]"),
    }


def _timeline(home: Path, reports: list[dict[str, Any]], *, limit: int) -> list[dict[str, Any]]:
    rows = []
    for event in read_audit_events(home, limit=100):
        runbook = str(event.get("runbook") or "")
        if runbook in COBUILD_READ_RUNBOOKS or str(event.get("event_type", "")).startswith("cobuild."):
            rows.append({"created_at": event.get("created_at"), "kind": event.get("event_type"), "runbook": runbook, "summary": event.get("summary") or event.get("project") or event.get("task_id")})
    for report in reports:
        result = report.get("result") or {}
        rows.append({"created_at": report.get("created_at") or result.get("completed_at"), "kind": "cobuild.report", "runbook": report.get("runbook") or result.get("runbook"), "summary": result.get("summary"), "task_id": report.get("task_id")})
    rows.sort(key=lambda item: float(item.get("created_at") or 0), reverse=True)
    return rows[:limit]


def _codex_handoff_text(alias: str, question: str, *, status: dict[str, Any], structure: dict[str, Any], deps: dict[str, Any], errors: dict[str, Any]) -> str:
    detected = ", ".join(status.get("detected_stack") or []) or "unknown"
    diagnostics = errors.get("diagnostics") or []
    diag_note = f"{len(diagnostics)} owner diagnostic file(s) included." if diagnostics else "No owner diagnostic files were present."
    return "\n".join(
        [
            "For Codex:",
            f"Review this GremlinChat co-build packet for project alias `{alias}`.",
            f"User question: {question or 'Help identify the next safe debugging step.'}",
            f"Detected stack: {detected}.",
            f"Git clean: {status.get('git', {}).get('clean')}.",
            f"Structure entries: {len(structure.get('entries', []))}. Dependency files: {deps.get('file_count', 0)}. {diag_note}",
            "Do not assume remote shell access. Suggest read-only checks or owner-approved changes only.",
        ]
    )


def _handoff_prompt(runbook: str, result: dict[str, Any], output: dict[str, Any], *, question: str | None) -> str:
    project = output.get("project") or output.get("status", {}).get("project") or {}
    alias = project.get("alias", "partner-project") if isinstance(project, dict) else "partner-project"
    return "\n".join(
        [
            "You are helping with a GremlinChat co-build debugging packet.",
            f"Project alias: {alias}",
            f"Runbook: {runbook}",
            f"Result: {result.get('status')} accepted={result.get('accepted')}",
            f"Question: {question or output.get('question') or 'Find the most likely blocker and next read-only checks.'}",
            "",
            "Use the attached redacted evidence. Do not request arbitrary remote shell or silent edits.",
        ]
    )


def _handoff_markdown(packet: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# GremlinChat Co-Build Handoff",
            "",
            f"- Task: `{packet.get('task_id')}`",
            f"- Room: `{packet.get('room_id')}`",
            f"- Runbook: `{packet.get('runbook')}`",
            f"- Status: `{packet.get('result_status')}`",
            "",
            "## Codex Prompt",
            "",
            str(packet.get("prompt") or ""),
            "",
            "## Evidence",
            "",
            "```json",
            json.dumps(packet.get("evidence", {}), indent=2, sort_keys=True),
            "```",
            "",
        ]
    )


def _safe_project_path(root: Path, rel: str) -> Path:
    path = (root / rel).resolve()
    if path != root and root not in path.parents:
        raise ValueError("path escapes project")
    return path


def _read_text_head(path: Path, *, limit: int) -> str:
    data = path.read_bytes()[:limit]
    return data.decode("utf-8", errors="replace")


def _read_text_tail(path: Path, *, limit: int) -> str:
    data = path.read_bytes()
    return data[-limit:].decode("utf-8", errors="replace")


def _safe_relative(path: Path) -> str:
    parts = ["[redacted-name]" if _sensitive_name(part) else part for part in path.parts]
    return "/".join(parts)


def _sensitive_path(path: Path) -> bool:
    return any(_sensitive_name(part) for part in path.parts)


def _sensitive_name(name: str) -> bool:
    lower = name.lower()
    return any(part in lower for part in SENSITIVE_NAME_PARTS)


def _redact_paths(base_text: str, value: Any) -> Any:
    if not isinstance(value, str):
        return value
    normalized = value.replace("\\", "/")
    if base_text and base_text in normalized:
        normalized = normalized.replace(base_text, "%COBUILD_PROJECT_ROOT%")
    normalized = re.sub(r"(?i)[A-Z]:/[^\s\"'<>]+", "[redacted-path]", normalized)
    return normalized


def _bounded_text(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[-limit:]
