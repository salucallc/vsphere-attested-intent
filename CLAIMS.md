# Claims

Every capability this repo's README or docs state, mapped to the code that does it, where it is
wired, and the test that proves it. The method itself is proposed, not implemented here.

| id | claim | source | status | code | wired | test | note |
|---|---|---|---|---|---|---|---|
| C1 | each one must be rejected | README.md | shipped | tools/validate_rules.py::check_file; tools/validate_rules.py::main | .github/workflows/sigma-validate.yml: python tools/validate_rules.py | tests/test_validate_rules.py::test_broken_rule_rejected | |
| C2 | Every rule must load in pySigma | README.md | shipped | tools/validate_rules.py::check_file | .github/workflows/sigma-validate.yml: python tools/validate_rules.py | tests/test_validate_rules.py::test_rule_is_clean | |
| C3 | A cross-file pass checks that ids and titles are unique | README.md | shipped | tools/validate_rules.py::main | .github/workflows/sigma-validate.yml: python tools/validate_rules.py | tests/test_validate_rules.py::test_main_fails_when_a_broken_rule_is_in_rules | |
| C4 | The method is proposed, not implemented here | README.md | planned | | | | attested intent is a method description; no attestation code ships in this repo |
