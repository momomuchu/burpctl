# Parser format precedence evidence

Candidate: `codex/fix-agent-parser` at `4379704` plus the working tree fix.

## RED

Invocation:

```text
cd bp && .venv/bin/pytest -q tests/test_agent_parser_errors.py -k last_explicit_format_wins_for_mixed_parser_options
```

Observed before the `cli.py` edit: `1 failed, 1 passed, 9 deselected`.
The failing case was `--format=json --format table no-such-command`: stderr was JSON even though the last explicit format was `table`.

## GREEN

Invocation:

```text
cd bp && .venv/bin/pytest -q tests/test_agent_parser_errors.py -k last_explicit_format_wins_for_mixed_parser_options
```

Observed after the edit: `2 passed, 9 deselected`.

## Installed CLI direct scenario

Invocation:

```text
BP_AGENT=1 bp/.venv/bin/bp --format=json --format table no-such-command
BP_AGENT=1 bp/.venv/bin/bp --format table --format=json no-such-command
```

Binary observables for both invocations: exit code `2`, stdout length `0`.

Expected and observed for the first invocation: human Click/Typer parser error beginning `Usage: bp`.

Expected and observed for the second invocation: one JSON stderr record:

```json
{"error":{"code":"USAGE_ERROR","message":"No such command 'no-such-command'."}}
```

## Regression checks

Invocation:

```text
cd bp && .venv/bin/pytest -q tests/test_agent_parser_errors.py tests/test_cli_global_opts.py
cd bp && .venv/bin/ruff check src/bp/cli.py tests/test_agent_parser_errors.py
cd bp && .venv/bin/mypy src/bp/cli.py tests/test_agent_parser_errors.py
```

Observed: `23 passed, 1 skipped`; Ruff `All checks passed!`; mypy `Success: no issues found in 2 source files`.
