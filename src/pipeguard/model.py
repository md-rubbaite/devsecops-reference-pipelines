"""Findings and the loaded representation of a workflow file."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any

import yaml


class Severity(IntEnum):
    NOTE = 1
    WARNING = 2
    ERROR = 3

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity '{value}' (use note, warning or error)") from exc


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    remediation: str


@dataclass(frozen=True)
class Finding:
    rule: Rule
    path: str
    line: int
    message: str


@dataclass
class Workflow:
    path: str
    text: str
    data: dict[str, Any]
    lines: list[str] = field(default_factory=list)

    @property
    def triggers(self) -> set[str]:
        # YAML 1.1 parses a bare `on:` key as boolean True.
        on = self.data.get("on", self.data.get(True))
        if isinstance(on, str):
            return {on}
        if isinstance(on, list):
            return {str(t) for t in on}
        if isinstance(on, dict):
            return {str(t) for t in on}
        return set()

    @property
    def jobs(self) -> dict[str, dict[str, Any]]:
        jobs = self.data.get("jobs") or {}
        return {str(k): v for k, v in jobs.items() if isinstance(v, dict)}

    def line_of(self, needle: str, start: int = 0) -> int:
        """1-based line of the first occurrence of ``needle`` at or after line ``start`` (0-based)."""
        for i in range(start, len(self.lines)):
            if needle in self.lines[i]:
                return i + 1
        return 1


def load_workflow(path: str | Path) -> Workflow:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"{p}: invalid YAML ({exc})") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{p}: not a workflow (top level is not a mapping)")
    return Workflow(path=str(p), text=text, data=data, lines=text.splitlines())
