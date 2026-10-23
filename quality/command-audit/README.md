# Command audit execution modes

The committed audit is a historical observation of product revision
`3af139dc0b4020923f831099338c92af3265d7e2` (`bp/src` tree
`73eabb36e5dc2abe80aace1daad1833ac864d18f`). Its 57 command forms, 114
normal/contrast cases, verdicts, and raw evidence remain immutable. A later product fix may
legitimately differ from those observations; that difference does not rewrite the audit.

Use the mode runner from the repository root:

```sh
uv run quality/command-audit/validate_command_audit.py baseline-replay
uv run quality/command-audit/validate_command_audit.py historical-live
uv run quality/command-audit/validate_command_audit.py current-candidate
```

| Mode | Contract | Failure means |
| --- | --- | --- |
| `baseline-replay` | Default. Rebuild the 114-case matrix in memory, verify all 60 bundled evidence digests, and compare the committed matrix and summary byte-for-byte. Historical subprocess probe modules are explicitly skipped. | Sealed evidence, provenance, the derived matrix, or its summary changed or became contradictory. |
| `historical-live` | Run the original installed-CLI probes only when the committed `bp/src` tree equals the historical tree above. | The historical source identity is wrong, or the original candidate no longer reproduces its recorded behavior. |
| `current-candidate` | Replay the immutable baseline, then run the current product's parser, preflight, and agent-output contract tests. The historical source tree is rejected. | The current source is not a new candidate, required candidate contract tests are missing, or a current public contract regressed. |

Plain `pytest` uses `baseline-replay`. The historical live modules carry an explicit source-tree
gate, so fixed product code cannot fail merely because an old defect disappeared. The
`current-candidate` mode uses `test_agent_parser_errors.py`, `test_agent_fuzz_preflight.py`, and
`test_agent_preflight_output.py` as the executable current contract; it does not compare fixed
output to historical buggy output.

The mode runner refuses uncommitted changes under `bp/src` for either live mode. `--no-pytest`
checks only sealed replay and source identity, which is useful for diagnosing a gate before running
the test process.
