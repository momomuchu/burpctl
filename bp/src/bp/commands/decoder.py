"""bp decoder commands — encode / decode / hash (docs/CLI.md §decoder, SPEC.md §6.9).

Endpoints (all Community — pure JVM, no Montoya, no Pro required):
  POST /decoder/encode       — encode data (base64 | url | hex | html)
  POST /decoder/decode       — decode data with explicit or auto-detected encoding
  POST /decoder/smart-decode — peel up to 10 encoding layers, trace each step
  POST /decoder/hash         — hash data (md5 | sha1 | sha256 | sha-384 | sha-512 …)

Request models (Kotlin source, SPEC §6.9):
  EncodeRequest  { data:String, encoding:String }   encoding ∈ {base64,url,hex,html}
  DecodeRequest  { data:String, encoding:String? }  null → auto-detect
  HashRequest    { data:String, algorithm:String }  md5/sha1/sha256/sha-384/sha-512 etc.

Caveats surfaced per SPEC:
  - html encoding covers only 5 entities (& < > " ').
  - smart-decode ignores the encoding field; always peels automatically.
  - auto-detect (decode without --enc) may mis-classify short/ambiguous inputs.
  - hash echoes the algorithm name as supplied, not the JVM-normalised name.
  - INVALID_REQUEST 400 on: encoding outside the accepted set, invalid base64,
    odd-length hex, or malformed JSON.
"""

from __future__ import annotations

from typing import Any

import typer

from bp.cliutil import EXIT_USAGE, run

_VALID_ENCODINGS = frozenset({"base64", "url", "hex", "html"})


def _check_enc(enc: str) -> None:
    """Validate --enc client-side; emit a clean error and exit 2 if invalid."""
    if enc not in _VALID_ENCODINGS:
        typer.echo(
            f"error: --enc must be one of base64, url, hex, html; got {enc!r}",
            err=True,
        )
        raise typer.Exit(EXIT_USAGE)

# ---------------------------------------------------------------------------
# Sub-application
# ---------------------------------------------------------------------------

sub = typer.Typer(no_args_is_help=True, help="Encoder / decoder / hasher (offline, pure JVM).")


# ---------------------------------------------------------------------------
# bp encode <data> --enc E
# ---------------------------------------------------------------------------


@sub.command(name="encode")
def encode_cmd(
    ctx: typer.Context,
    data: str = typer.Argument(..., metavar="DATA", help="String to encode."),
    enc: str = typer.Option(
        ...,
        "--enc",
        help="Encoding scheme: base64 | url | hex | html",
        metavar="E",
    ),
) -> None:
    """Encode DATA with the given scheme (POST /decoder/encode).

    Supported encodings: base64, url, hex, html.
    html encodes only 5 entities: & < > \" '
    """
    _check_enc(enc)
    body: dict[str, Any] = {"data": data, "encoding": enc}
    run(ctx, lambda c: c.post("/decoder/encode", body))


# ---------------------------------------------------------------------------
# bp decode <data> [--enc E | --smart]
# ---------------------------------------------------------------------------


@sub.command(name="decode")
def decode_cmd(
    ctx: typer.Context,
    data: str = typer.Argument(..., metavar="DATA", help="String to decode."),
    enc: str | None = typer.Option(
        None,
        "--enc",
        help="Encoding scheme: base64 | url | hex | html  (omit for auto-detect).",
        metavar="E",
    ),
    smart: bool = typer.Option(
        False,
        "--smart",
        help="Peel up to 10 encoding layers automatically, tracing each step.",
        is_flag=True,
    ),
) -> None:
    """Decode DATA using an explicit scheme, auto-detect, or smart multi-layer mode.

    Without flags: POST /decoder/decode with encoding=null → server auto-detects.
    With --enc E:   POST /decoder/decode with explicit encoding.
    With --smart:   POST /decoder/smart-decode (encoding field is ignored by server;
                    server peels up to 10 layers and returns each DecodeStep).

    NOTE: auto-detect may mis-classify short or ambiguous inputs.
    NOTE: --smart ignores --enc even if both are supplied.
    """
    if smart:
        # encoding field is silently ignored by smart-decode — pass data only
        body: dict[str, Any] = {"data": data}
        run(ctx, lambda c: c.post("/decoder/smart-decode", body))
    else:
        if enc is not None:
            _check_enc(enc)
        body = {"data": data}
        if enc is not None:
            body["encoding"] = enc
        run(ctx, lambda c: c.post("/decoder/decode", body))


# ---------------------------------------------------------------------------
# bp hash <data> --algo A
# ---------------------------------------------------------------------------


@sub.command(name="hash")
def hash_cmd(
    ctx: typer.Context,
    data: str = typer.Argument(..., metavar="DATA", help="String to hash."),
    algo: str = typer.Option(
        ...,
        "--algo",
        help="Hash algorithm: md5 | sha1 | sha256 | sha-384 | sha-512 (or raw JVM name).",
        metavar="A",
    ),
) -> None:
    """Hash DATA with the given algorithm (POST /decoder/hash).

    Common algorithms: md5, sha1, sha256, sha-384, sha-512.
    The server echoes the algorithm name as supplied (not the JVM-normalised form).
    Useful for comparing a token against a candidate hash value.
    """
    body: dict[str, Any] = {"data": data, "algorithm": algo}
    run(ctx, lambda c: c.post("/decoder/hash", body))


# ---------------------------------------------------------------------------
# Registration entry-point
# ---------------------------------------------------------------------------


def register(app: typer.Typer) -> None:
    """Register encode, decode, hash as FLAT top-level commands on *app*."""
    app.command(name="encode")(encode_cmd)
    app.command(name="decode")(decode_cmd)
    app.command(name="hash")(hash_cmd)
