import textwrap
from pathlib import Path

import pytest

from pipeguard.model import Workflow, load_workflow
from pipeguard.rules import scan

ROOT = Path(__file__).resolve().parents[1]
FAKE_SHA = "0123456789abcdef0123456789abcdef01234567"  # test data only


def wf(yaml_text: str, tmp_path: Path) -> Workflow:
    p = tmp_path / "w.yml"
    p.write_text(textwrap.dedent(yaml_text))
    return load_workflow(p)


def ids(findings) -> list[str]:
    return sorted(f.rule.id for f in findings)


def test_insecure_example_triggers_every_rule():
    found = set(ids(scan(load_workflow(ROOT / "examples/insecure/ci.yml"))))
    assert found == {"PG002", "PG003", "PG004", "PG005", "PG006", "PG007", "PG008", "PG009", "PG010"}


def test_hardened_example_has_no_errors_or_warnings(tmp_path):
    text = (ROOT / "examples/hardened/ci.yml").read_text()
    if "__PIN:" in text:  # placeholders are replaced with real SHAs when published
        text = text.replace("__PIN:actions/checkout__", FAKE_SHA)
    findings = scan(wf(text, tmp_path))
    assert ids(findings) == []


def test_missing_permissions(tmp_path):
    findings = scan(
        wf(
            """
        on: push
        jobs:
          a: {runs-on: ubuntu-latest, steps: [{run: make}]}
    """,
            tmp_path,
        )
    )
    assert ids(findings) == ["PG001"]


def test_job_level_permissions_satisfy_pg001(tmp_path):
    findings = scan(
        wf(
            """
        on: push
        jobs:
          a: {runs-on: ubuntu-latest, permissions: {contents: read}, steps: [{run: make}]}
    """,
            tmp_path,
        )
    )
    assert ids(findings) == []


def test_reusable_workflow_call_does_not_need_its_own_permissions(tmp_path):
    findings = scan(
        wf(
            f"""
        on: push
        jobs:
          a: {{uses: org/repo/.github/workflows/ci.yml@{FAKE_SHA}}}
    """,
            tmp_path,
        )
    )
    assert ids(findings) == []


@pytest.mark.parametrize(
    ("ref", "expected"),
    [
        (f"actions/checkout@{FAKE_SHA}", []),
        ("actions/checkout@v4", ["PG003"]),
        ("org/x@main", ["PG004"]),
        ("org/x@v1.2.3", ["PG003"]),
        ("./local-action", []),
        ("docker://alpine:3.20", []),
    ],
)
def test_pinning(tmp_path, ref, expected):
    findings = scan(
        wf(
            f"""
        on: push
        permissions: {{contents: read}}
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - uses: {ref}
                with: {{persist-credentials: false}}
    """,
            tmp_path,
        )
    )
    assert ids(findings) == expected


@pytest.mark.parametrize(
    "expr",
    [
        "github.event.issue.title",
        "github.event.pull_request.body",
        "github.head_ref",
        "github.event.comment.body",
        "github.event.head_commit.message",
        "github.event.pull_request.head.ref",
    ],
)
def test_script_injection_sources(tmp_path, expr):
    findings = scan(
        wf(
            f"""
        on: issues
        permissions: {{contents: read}}
        jobs:
          a: {{runs-on: ubuntu-latest, steps: [{{run: "echo ${{{{ {expr} }}}}"}}]}}
    """,
            tmp_path,
        )
    )
    assert ids(findings) == ["PG005"]


def test_trusted_context_values_are_not_flagged(tmp_path):
    findings = scan(
        wf(
            """
        on: push
        permissions: {contents: read}
        jobs:
          a: {runs-on: ubuntu-latest, steps: [{run: "echo ${{ github.sha }} ${{ github.event.pull_request.number }}"}]}
    """,
            tmp_path,
        )
    )
    assert ids(findings) == []


def test_env_indirection_is_the_safe_pattern(tmp_path):
    findings = scan(
        wf(
            """
        on: issues
        permissions: {contents: read}
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - env: {TITLE: "${{ github.event.issue.title }}"}
                run: echo "$TITLE"
    """,
            tmp_path,
        )
    )
    assert ids(findings) == []


def test_pull_request_target_without_head_checkout_is_allowed(tmp_path):
    findings = scan(
        wf(
            f"""
        on: pull_request_target
        permissions: {{pull-requests: write}}
        jobs:
          label:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/labeler@{FAKE_SHA}
    """,
            tmp_path,
        )
    )
    assert ids(findings) == []


def test_bare_on_key_parsed_as_boolean_is_handled(tmp_path):
    w = wf(
        """
        on: [push, pull_request]
        permissions: {contents: read}
        jobs:
          a: {runs-on: [self-hosted, linux], steps: [{run: make}]}
    """,
        tmp_path,
    )
    assert w.triggers == {"push", "pull_request"}
    assert ids(scan(w)) == ["PG010"]


def test_findings_point_at_the_right_line():
    findings = scan(load_workflow(ROOT / "examples/insecure/ci.yml"))
    pg007 = next(f for f in findings if f.rule.id == "PG007")
    line = (ROOT / "examples/insecure/ci.yml").read_text().splitlines()[pg007.line - 1]
    assert "curl" in line
