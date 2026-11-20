"""Validate the SIGMA rules in rules/ with pySigma, and prove the validator can fail.

Usage:
    python tools/validate_rules.py            # validate rules/, then run the self-test
    python tools/validate_rules.py --no-self-test

Exit codes: 0 every rule is clean AND every planted-broken rule was rejected; 1 otherwise.

What it checks, per rule in rules/:
  1. The file parses and loads as a SigmaRule (pySigma raises on a bad id, modifier,
     level, or a condition naming an undefined selection).
  2. Every pySigma core validator reports no issue (ATT&CK tags are checked against the
     ATT&CK data pySigma fetches at run time).
  3. House checks: status is experimental, the first line carries "untested in a lab",
     and the author is "Saluca Labs". These rules are untested drafts and must say so.

The self-test runs the same checks on every file in tests/broken/. Each one carries a
single deliberate defect, and each one must be REJECTED. A broken rule that passes means
the validator is not testing anything, which is itself a failure.

What it does NOT check: whether a rule detects anything. Syntax is not behaviour. No rule
here has been run against live vCenter or ESXi data.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.validation import SigmaValidator
from sigma.validators.core import validators

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
BROKEN = ROOT / "tests" / "broken"

UNTESTED_MARK = "untested in a lab"


def check_file(path: Path) -> list[str]:
    """Return a list of problems for one rule file. Empty means clean."""
    problems: list[str] = []
    text = path.read_text(encoding="utf-8")
    first_line = text.splitlines()[0] if text else ""
    if UNTESTED_MARK not in first_line.lower():
        problems.append(f'first line does not say "{UNTESTED_MARK}"')

    try:
        collection = SigmaCollection.from_yaml(text, collect_errors=True)
    except SigmaError as exc:
        return problems + [f"load error: {exc}"]
    except Exception as exc:  # malformed YAML and similar: cannot tell is a failure
        return problems + [f"parse error: {type(exc).__name__}: {exc}"]

    if len(collection.rules) != 1:
        problems.append(f"expected exactly one rule, found {len(collection.rules)}")
    for rule in collection.rules:
        for err in rule.errors:
            problems.append(f"rule error: {type(err).__name__}: {err}")
        if not rule.errors:
            try:
                rule.detection.parsed_condition[0].parse()
            except SigmaError as exc:
                problems.append(f"condition error: {exc}")
        status = str(rule.status).lower() if rule.status else ""
        if "experimental" not in status:
            problems.append(f"status must be experimental, is {rule.status}")
        if rule.author != "Saluca Labs":
            problems.append(f"author must be Saluca Labs, is {rule.author!r}")

    if not problems or all(p.startswith("first line") for p in problems):
        validator = SigmaValidator(validators.values())
        for issue in validator.validate_rules(collection.rules):
            problems.append(f"validator: {type(issue).__name__}: {issue}")
    return problems


def run(paths: list[Path]) -> dict[Path, list[str]]:
    return {p: check_file(p) for p in paths}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--no-self-test", action="store_true")
    args = parser.parse_args()

    rules = sorted(RULES.glob("*.yml"))
    if not rules:
        print("FAIL: no rules found in rules/ (an empty set is not a pass)")
        return 1

    failed = False
    print(f"Validating {len(rules)} rules in {RULES.name}/")
    for path, problems in run(rules).items():
        if problems:
            failed = True
            print(f"  FAIL {path.name}")
            for p in problems:
                print(f"       - {p}")
        else:
            print(f"  ok   {path.name}")

    # Cross-file pass: duplicate ids, titles and filenames only show up across the set.
    combined = SigmaCollection.from_yaml(
        "\n---\n".join(p.read_text(encoding="utf-8") for p in rules), collect_errors=True
    )
    cross = SigmaValidator(validators.values()).validate_rules(combined.rules)
    if len(combined.rules) != len(rules):
        failed = True
        print(f"  FAIL cross-file: loaded {len(combined.rules)} rules from {len(rules)} files")
    for issue in cross:
        failed = True
        print(f"  FAIL cross-file: {type(issue).__name__}: {issue}")
    if not cross and len(combined.rules) == len(rules):
        print(f"  ok   cross-file: {len(combined.rules)} rules, ids and titles unique")

    if not args.no_self_test:
        broken = sorted(BROKEN.glob("*.yml"))
        if not broken:
            print("FAIL: no planted-broken rules in tests/broken/; the validator is unproven")
            return 1
        print(f"Self-test: {len(broken)} planted-broken rules must each be rejected")
        for path, problems in run(broken).items():
            if problems:
                print(f"  rejected {path.name}: {problems[0]}")
            else:
                failed = True
                print(f"  FAIL {path.name} was ACCEPTED; the validator missed a planted defect")

    print("RESULT:", "FAIL" if failed else "PASS (syntax and tags only; untested in a lab)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
