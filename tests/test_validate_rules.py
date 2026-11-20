"""Tests for tools/validate_rules.py.

The point of these tests is that the validator can fail: every planted-broken rule must be
rejected, and a clean rule must pass, so the validator is neither accepting everything nor
rejecting everything.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("validate_rules", ROOT / "tools" / "validate_rules.py")
validate_rules = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(validate_rules)

RULES = sorted((ROOT / "rules").glob("*.yml"))
BROKEN = sorted((ROOT / "tests" / "broken").glob("*.yml"))


def test_there_are_nine_rules():
    assert len(RULES) == 9


@pytest.mark.parametrize("path", RULES, ids=lambda p: p.name)
def test_rule_is_clean(path):
    assert validate_rules.check_file(path) == []


@pytest.mark.parametrize("path", BROKEN, ids=lambda p: p.name)
def test_broken_rule_rejected(path):
    assert validate_rules.check_file(path), f"{path.name} carries a planted defect and was accepted"


def test_every_broken_fixture_has_a_clean_twin(tmp_path):
    """Each planted defect is a one-line change to a real rule. Undoing it must give a clean
    rule, so the rejection is caused by the defect and not by something else in the file."""
    base = (ROOT / "rules" / "vmw_network_bearbones_ssh_banner.yml").read_text(encoding="utf-8")
    assert len(BROKEN) == 6
    for path in BROKEN:
        text = path.read_text(encoding="utf-8")
        assert text != base
    clean = tmp_path / "control.yml"
    clean.write_text(base, encoding="utf-8")
    assert validate_rules.check_file(clean) == []


def test_main_fails_when_a_broken_rule_is_in_rules(tmp_path, monkeypatch, capsys):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    for p in RULES:
        (rules_dir / p.name).write_text(p.read_text(encoding="utf-8"), encoding="utf-8")
    (rules_dir / "zz_broken.yml").write_text(
        (ROOT / "tests" / "broken" / "bad_level.yml").read_text(encoding="utf-8").replace(
            "80f3b48a-88d9-4f79-aefe-e38d3b57e2c4", "0c6a0f3e-7c0e-4d55-9a57-0b1f6b8f4b11"
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(validate_rules, "RULES", rules_dir)
    monkeypatch.setattr("sys.argv", ["validate_rules.py", "--no-self-test"])
    assert validate_rules.main() == 1
    assert "FAIL zz_broken.yml" in capsys.readouterr().out
