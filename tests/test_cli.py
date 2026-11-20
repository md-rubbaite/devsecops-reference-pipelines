import json
from pathlib import Path

from pipeguard.cli import main

ROOT = Path(__file__).resolve().parents[1]


def test_insecure_example_fails_and_hardened_policy_passes(capsys):
    assert main(["scan", str(ROOT / "examples/insecure")]) == 1
    out = capsys.readouterr().out
    assert "PG006" in out and "fix:" in out


def test_fail_on_threshold(tmp_path):
    p = tmp_path / "w.yml"
    p.write_text(
        "on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/checkout@v4\n        with: {persist-credentials: false}\n"
    )
    assert main(["scan", str(p)]) == 0  # only a warning
    assert main(["scan", str(p), "--fail-on", "warning"]) == 1


def test_sarif_output_is_valid_and_complete(tmp_path):
    out = tmp_path / "r.sarif"
    main(["scan", str(ROOT / "examples/insecure"), "--format", "sarif", "--output", str(out)])
    doc = json.loads(out.read_text())
    run = doc["runs"][0]
    assert doc["version"] == "2.1.0"
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} >= {"PG001", "PG010"}
    assert all(r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1 for r in run["results"])
    assert {r["level"] for r in run["results"]} <= {"error", "warning", "note"}


def test_invalid_input_exits_2(tmp_path, capsys):
    bad = tmp_path / "bad.yml"
    bad.write_text("on: [push\n")
    assert main(["scan", str(bad)]) == 2
    assert main(["scan", str(tmp_path / "missing")]) == 2
    assert main(["scan", str(ROOT / "examples"), "--fail-on", "fatal"]) == 2
