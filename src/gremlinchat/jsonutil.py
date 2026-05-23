"""Deterministic JSON helpers."""

from __future__ import annotations

import json
from typing import Any


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_bytes(data: Any) -> bytes:
    return canonical_json(data).encode("utf-8")

