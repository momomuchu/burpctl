"""[40] RED tests — bp encode/decode --enc client-side allowlist validation.

bp decode foo --enc rot13 (invalid encoding) must exit 2 with a hint about
valid values, NOT exit 1 from a server INVALID_REQUEST.
No Burp required: the check happens client-side before any network call.
"""

from __future__ import annotations

import subprocess
import sys


def test_decode_bad_enc_exits_usage() -> None:
    """[40] --enc with an unsupported value → exit 2 (EXIT_USAGE), not exit 1."""
    entry = (
        "import os; os.environ['BURP_REST_URL']='http://127.0.0.1:9999'; "
        "import sys; sys.argv=['bp','decode','foo','--enc','rot13']; "
        "from bp.cli import cli_main; cli_main()"
    )
    r = subprocess.run([sys.executable, "-c", entry], capture_output=True, text=True)
    assert r.returncode == 2, (
        f"expected exit 2 (EXIT_USAGE), got {r.returncode}\nstderr={r.stderr!r}"
    )


def test_decode_bad_enc_shows_valid_values() -> None:
    """[40] --enc with bad value → stderr contains 'base64, url, hex, html' hint."""
    entry = (
        "import os; os.environ['BURP_REST_URL']='http://127.0.0.1:9999'; "
        "import sys; sys.argv=['bp','decode','foo','--enc','rot13']; "
        "from bp.cli import cli_main; cli_main()"
    )
    r = subprocess.run([sys.executable, "-c", entry], capture_output=True, text=True)
    # The error message must name the allowed values.
    combined = r.stderr + r.stdout
    assert "base64" in combined, f"expected valid-values hint in output:\n{combined!r}"
    assert "url" in combined, f"expected 'url' in valid-values hint:\n{combined!r}"


def test_encode_bad_enc_exits_usage() -> None:
    """[40] bp encode with bad --enc → exit 2 (EXIT_USAGE)."""
    entry = (
        "import os; os.environ['BURP_REST_URL']='http://127.0.0.1:9999'; "
        "import sys; sys.argv=['bp','encode','foo','--enc','rot13']; "
        "from bp.cli import cli_main; cli_main()"
    )
    r = subprocess.run([sys.executable, "-c", entry], capture_output=True, text=True)
    assert r.returncode == 2, (
        f"expected exit 2 (EXIT_USAGE), got {r.returncode}\nstderr={r.stderr!r}"
    )


def test_decode_auto_detect_unaffected() -> None:
    """[40] bp decode without --enc (auto-detect) must reach the network, not exit 2 early.

    Pointing at a dead port → exit 3 (conn refused), proving no client-side
    validation fired for the auto-detect path.
    """
    entry = (
        "import os; os.environ['BURP_REST_URL']='http://127.0.0.1:9999'; "
        "import sys; sys.argv=['bp','decode','foo']; "
        "from bp.cli import cli_main; cli_main()"
    )
    r = subprocess.run([sys.executable, "-c", entry], capture_output=True, text=True)
    assert r.returncode == 3, (
        f"expected exit 3 (conn refused for auto-detect path), got {r.returncode}\nstderr={r.stderr!r}"
    )


def test_decode_valid_enc_reaches_network() -> None:
    """[40] bp decode with a valid --enc value must reach the network (exit 3 at dead port)."""
    entry = (
        "import os; os.environ['BURP_REST_URL']='http://127.0.0.1:9999'; "
        "import sys; sys.argv=['bp','decode','aGVsbG8=','--enc','base64']; "
        "from bp.cli import cli_main; cli_main()"
    )
    r = subprocess.run([sys.executable, "-c", entry], capture_output=True, text=True)
    assert r.returncode == 3, (
        f"expected exit 3 (conn refused for valid enc), got {r.returncode}\nstderr={r.stderr!r}"
    )
