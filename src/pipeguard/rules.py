"""Security rules for GitHub Actions workflows.

Each rule targets a misconfiguration that has been used in real supply-chain attacks on CI/CD:
over-privileged tokens, untrusted input in shell commands, unpinned third-party code and
privileged triggers that run code from forks.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from typing import Any

from .model import Finding, Rule, Severity, Workflow

PG001 = Rule(
    "PG001",
    "No top-level permissions",
    Severity.ERROR,
    "Add `permissions: contents: read` at the top level and grant more per job only where needed.",
)
PG002 = Rule(
    "PG002",
    "Over-broad token permissions",
    Severity.ERROR,
    "Replace `write-all` with the specific scopes the job needs.",
)
PG003 = Rule(
    "PG003",
    "Action not pinned to a commit SHA",
    Severity.WARNING,
    "Pin to a full 40-character commit SHA and keep the version in a comment; let Dependabot update it.",
)
PG004 = Rule(
    "PG004",
    "Action pinned to a branch",
    Severity.ERROR,
    "Branches move. Pin to a commit SHA (or at least a release tag).",
)
PG005 = Rule(
    "PG005",
    "Untrusted input interpolated into a shell command",
    Severity.ERROR,
    "Pass the value through `env:` and reference it as a quoted shell variable.",
)
PG006 = Rule(
    "PG006",
    "pull_request_target checks out the pull request's code",
    Severity.ERROR,
    "Use `pull_request` for untrusted code, or never check out the PR head in a privileged trigger.",
)
PG007 = Rule(
    "PG007",
    "Remote script piped into a shell",
    Severity.ERROR,
    "Download to a file, verify a checksum or signature, then execute.",
)
PG008 = Rule(
    "PG008",
    "Secret written to the log",
    Severity.ERROR,
    "Never echo secrets; pass them via `env:` to the tool that needs them.",
)
PG009 = Rule(
    "PG009",
    "Checkout keeps the token in .git/config",
    Severity.NOTE,
    "Set `persist-credentials: false` unless later steps must push.",
)
PG010 = Rule(
    "PG010",
    "Self-hosted runner on a pull-request trigger",
    Severity.WARNING,
    "Run untrusted pull requests on ephemeral GitHub-hosted runners.",
)

ALL_RULES = [PG001, PG002, PG003, PG004, PG005, PG006, PG007, PG008, PG009, PG010]

SHA = re.compile(r"^[0-9a-f]{40}$")
BRANCHES = {"main", "master", "develop", "dev", "trunk", "HEAD"}
# Fields an outside contributor controls. Interpolating them into `run:` lets them inject shell.
UNTRUSTED = re.compile(
    r"\$\{\{\s*(github\.head_ref|github\.event\.(issue|pull_request|comment|review|review_comment|discussion|"
    r"head_commit|commits|pages|workflow_run)[^}]*?\.(title|body|message|name|label|ref|email|default_branch|"
    r"head_ref|page_name))\s*\}\}"
)
PIPE_TO_SHELL = re.compile(r"\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|k)?sh\b")
ECHO_SECRET = re.compile(r"\b(echo|printf|cat)\b[^\n]*\$\{\{\s*secrets\.")
PR_HEAD = re.compile(r"github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref|refs/pull/")


def _steps(job: dict[str, Any]) -> Iterator[dict[str, Any]]:
    for step in job.get("steps") or []:
        if isinstance(step, dict):
            yield step


def check_permissions(wf: Workflow) -> Iterator[Finding]:
    if "permissions" not in wf.data:
        unscoped = [name for name, job in wf.jobs.items() if "permissions" not in job and "uses" not in job]
        if unscoped:
            yield Finding(
                PG001,
                wf.path,
                wf.line_of("jobs:"),
                f"Jobs {', '.join(unscoped)} run with the repository's default token permissions.",
            )
    for scope, where in [(wf.data.get("permissions"), "workflow")] + [
        (job.get("permissions"), f"job '{name}'") for name, job in wf.jobs.items()
    ]:
        if scope == "write-all":
            yield Finding(PG002, wf.path, wf.line_of("write-all"), f"{where} grants write-all.")


def check_pinning(wf: Workflow) -> Iterator[Finding]:
    for name, job in wf.jobs.items():
        refs = [job["uses"]] if isinstance(job.get("uses"), str) else []
        refs += [s["uses"] for s in _steps(job) if isinstance(s.get("uses"), str)]
        for ref in refs:
            if ref.startswith(("./", "docker://")) or "@" not in ref:
                continue
            version = ref.rsplit("@", 1)[1]
            if version in BRANCHES:
                yield Finding(PG004, wf.path, wf.line_of(ref), f"{ref} in job '{name}' follows a branch.")
            elif not SHA.match(version):
                yield Finding(PG003, wf.path, wf.line_of(ref), f"{ref} in job '{name}' is pinned to a mutable tag.")


def check_run_steps(wf: Workflow) -> Iterator[Finding]:
    for name, job in wf.jobs.items():
        for step in _steps(job):
            run = step.get("run")
            if not isinstance(run, str):
                continue
            anchor = wf.line_of(run.splitlines()[0]) if run.strip() else 1
            for m in UNTRUSTED.finditer(run):
                yield Finding(PG005, wf.path, anchor, f"`{m.group(0)}` in job '{name}' reaches the shell unquoted.")
            if PIPE_TO_SHELL.search(run):
                yield Finding(PG007, wf.path, anchor, f"Job '{name}' pipes a download straight into a shell.")
            if ECHO_SECRET.search(run):
                yield Finding(PG008, wf.path, anchor, f"Job '{name}' writes a secret to standard output.")


def check_privileged_triggers(wf: Workflow) -> Iterator[Finding]:
    triggers = wf.triggers
    if "pull_request_target" in triggers:
        for name, job in wf.jobs.items():
            for step in _steps(job):
                uses = str(step.get("uses", ""))
                ref = str((step.get("with") or {}).get("ref", ""))
                if uses.startswith("actions/checkout") and PR_HEAD.search(ref):
                    yield Finding(
                        PG006,
                        wf.path,
                        wf.line_of("ref:"),
                        f"Job '{name}' runs fork code with a write token and secrets.",
                    )
    if triggers & {"pull_request", "pull_request_target"}:
        for name, job in wf.jobs.items():
            runs_on = job.get("runs-on")
            labels = runs_on if isinstance(runs_on, list) else [runs_on]
            if "self-hosted" in [str(x) for x in labels]:
                yield Finding(
                    PG010, wf.path, wf.line_of("self-hosted"), f"Job '{name}' runs PR code on a self-hosted runner."
                )


def check_checkout_credentials(wf: Workflow) -> Iterator[Finding]:
    for name, job in wf.jobs.items():
        for step in _steps(job):
            uses = str(step.get("uses", ""))
            if uses.startswith("actions/checkout") and (step.get("with") or {}).get("persist-credentials") is not False:
                yield Finding(
                    PG009,
                    wf.path,
                    wf.line_of("actions/checkout"),
                    f"Checkout in job '{name}' leaves the token on disk.",
                )


CHECKS: list[Callable[[Workflow], Iterator[Finding]]] = [
    check_permissions,
    check_pinning,
    check_run_steps,
    check_privileged_triggers,
    check_checkout_credentials,
]


def scan(wf: Workflow) -> list[Finding]:
    findings = [f for check in CHECKS for f in check(wf)]
    return sorted(findings, key=lambda f: (f.path, f.line, f.rule.id))
