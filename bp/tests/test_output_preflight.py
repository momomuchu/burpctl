"""Effect-free validation for response-independent output option errors."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import typer

from bp.cliutil import EXIT_USAGE, State, run


@pytest.mark.parametrize("fmt", ["raw", "quiet"])
def test_incompatible_fields_fail_before_ledger_or_rest(
    fmt: str, capsys: pytest.CaptureFixture[str]
) -> None:
    ctx = MagicMock(spec=typer.Context)
    ctx.obj = State(
        url="http://127.0.0.1:8089",
        fmt=fmt,
        fields=["id"],
        no_ledger=False,
        no_redact=True,
    )
    ctx.command_path = "bp history replay"
    rest_operation = MagicMock()

    with (
        patch("bp.cliutil.Ledger") as ledger_cls,
        patch("bp.cliutil.BurpClient") as client_cls,
    ):
        with pytest.raises(typer.Exit) as exc_info:
            run(ctx, rest_operation)

    assert exc_info.value.exit_code == EXIT_USAGE
    assert capsys.readouterr() == ("", f"error: --fields is not valid with --format {fmt}\n")
    ledger_cls.assert_not_called()
    client_cls.assert_not_called()
    rest_operation.assert_not_called()
