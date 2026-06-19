"""Run Ledger — SQLite persistence for bp operations (ADR-0005, STATE-AND-CONFIG §1).

Database: ~/.bp/ledger.db  (table: ops)
NEVER stores raw request/response bodies — only sha256 fingerprints + optional refs.
Bodies may be opt-in via --ledger-bodies (writes to ~/.bp/blobs/<sha256> AFTER redaction).

Public API
----------
record(op)          -> str         Insert one row; returns the generated id.
query(filters)      -> list[Row]   SELECT with optional filters.
tag(id, name)       -> bool        UPDATE ops SET tag=name WHERE id=id.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# ULID-lite: sortable short id without external deps
# ---------------------------------------------------------------------------

import random
import string

_CHARS = string.ascii_lowercase + string.digits


def _short_id() -> str:
    """Return a ~12-char time-prefixed pseudo-random id (no external deps)."""
    ts = datetime.now(timezone.utc)
    prefix = ts.strftime("%Y%m%d%H%M%S")
    suffix = "".join(random.choices(_CHARS, k=6))
    return f"{prefix}{suffix}"


# ---------------------------------------------------------------------------
# Default ledger path
# ---------------------------------------------------------------------------

def _default_db_path() -> Path:
    return Path(os.environ.get("BP_LEDGER_PATH", "~/.bp/ledger.db")).expanduser()


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_DDL = """
CREATE TABLE IF NOT EXISTS ops (
  id          TEXT PRIMARY KEY,
  ts          TEXT NOT NULL,
  command     TEXT,
  burp_op     TEXT,
  target      TEXT,
  program     TEXT,
  tag         TEXT,
  status      TEXT NOT NULL,
  exit_code   INTEGER,
  req_sha256  TEXT,
  resp_sha256 TEXT,
  resp_status INTEGER,
  resp_len    INTEGER,
  duration_ms INTEGER,
  error_code  TEXT,
  req_ref     TEXT,
  resp_ref    TEXT
);
CREATE INDEX IF NOT EXISTS idx_ops_ts     ON ops(ts);
CREATE INDEX IF NOT EXISTS idx_ops_target ON ops(target);
CREATE INDEX IF NOT EXISTS idx_ops_tag    ON ops(tag);
"""

# Column order must match INSERT and Row below
_COLUMNS = (
    "id",
    "ts",
    "command",
    "burp_op",
    "target",
    "program",
    "tag",
    "status",
    "exit_code",
    "req_sha256",
    "resp_sha256",
    "resp_status",
    "resp_len",
    "duration_ms",
    "error_code",
    "req_ref",
    "resp_ref",
)


# ---------------------------------------------------------------------------
# Public data types
# ---------------------------------------------------------------------------

@dataclass
class OpRecord:
    """Input record for ledger.record().  Only 'status' is required."""

    status: str                        # ok | error | refused
    command: str | None = None         # redacted bp command line
    burp_op: str | None = None         # e.g. "POST /intruder/attack/create"
    target: str | None = None          # host / url targeted
    program: str | None = None         # nullable workspace (ADR-0007)
    tag: str | None = None
    exit_code: int | None = None
    req_body: bytes | None = None      # used ONLY for sha256; never stored
    resp_body: bytes | None = None     # used ONLY for sha256; never stored
    resp_status: int | None = None
    resp_len: int | None = None
    duration_ms: int | None = None
    error_code: str | None = None
    req_ref: str | None = None
    resp_ref: str | None = None


@dataclass
class Row:
    """One ops row returned by query()."""

    id: str
    ts: str
    command: str | None
    burp_op: str | None
    target: str | None
    program: str | None
    tag: str | None
    status: str
    exit_code: int | None
    req_sha256: str | None
    resp_sha256: str | None
    resp_status: int | None
    resp_len: int | None
    duration_ms: int | None
    error_code: str | None
    req_ref: str | None
    resp_ref: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "ts": self.ts,
            "command": self.command,
            "burp_op": self.burp_op,
            "target": self.target,
            "program": self.program,
            "tag": self.tag,
            "status": self.status,
            "exit_code": self.exit_code,
            "req_sha256": self.req_sha256,
            "resp_sha256": self.resp_sha256,
            "resp_status": self.resp_status,
            "resp_len": self.resp_len,
            "duration_ms": self.duration_ms,
            "error_code": self.error_code,
            "req_ref": self.req_ref,
            "resp_ref": self.resp_ref,
        }


@dataclass
class QueryFilters:
    since: str | None = None     # ISO-8601; ops WHERE ts >= since
    until: str | None = None     # ISO-8601; ops WHERE ts <= until
    target: str | None = None    # exact match on target
    tag: str | None = None       # exact match on tag
    status: str | None = None    # ok | error | refused
    limit: int = field(default=100)


# ---------------------------------------------------------------------------
# sha256 helper — bodies never stored, only fingerprint
# ---------------------------------------------------------------------------

def _sha256(data: bytes | None) -> str | None:
    if data is None:
        return None
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------

class Ledger:
    """Thin wrapper around a SQLite ops table."""

    def __init__(self, db_path: Path | None = None) -> None:
        self._path = db_path or _default_db_path()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_DDL)
        self._conn.commit()

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass

    def __enter__(self) -> "Ledger":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # record
    # ------------------------------------------------------------------

    def record(self, op: OpRecord) -> str:
        """Insert one ops row; return the generated id.

        req_body / resp_body are hashed to sha256 and then discarded —
        raw bytes are NEVER written to the database.

        ADR-0005: sqlite3.Error is caught, a one-line warning is printed to stderr,
        and an empty string is returned so the caller can proceed without crashing.
        """
        op_id = _short_id()
        ts = datetime.now(timezone.utc).isoformat()
        req_sha256 = _sha256(op.req_body)
        resp_sha256 = _sha256(op.resp_body)

        try:
            self._conn.execute(
                f"INSERT INTO ops ({', '.join(_COLUMNS)}) VALUES ({', '.join('?' * len(_COLUMNS))})",
                (
                    op_id,
                    ts,
                    op.command,
                    op.burp_op,
                    op.target,
                    op.program,
                    op.tag,
                    op.status,
                    op.exit_code,
                    req_sha256,
                    resp_sha256,
                    op.resp_status,
                    op.resp_len,
                    op.duration_ms,
                    op.error_code,
                    op.req_ref,
                    op.resp_ref,
                ),
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            import sys
            print(f"warning: ledger write failed: {exc}", file=sys.stderr)
            return ""
        return op_id

    # ------------------------------------------------------------------
    # query
    # ------------------------------------------------------------------

    def query(self, filters: QueryFilters | None = None) -> list[Row]:
        """SELECT ops rows matching *filters*, newest first."""
        f = filters or QueryFilters()
        clauses: list[str] = []
        params: list[Any] = []

        if f.since is not None:
            clauses.append("ts >= ?")
            params.append(f.since)
        if f.until is not None:
            clauses.append("ts <= ?")
            params.append(f.until)
        if f.target is not None:
            clauses.append("target = ?")
            params.append(f.target)
        if f.tag is not None:
            clauses.append("tag = ?")
            params.append(f.tag)
        if f.status is not None:
            clauses.append("status = ?")
            params.append(f.status)

        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM ops{where} ORDER BY ts DESC LIMIT ?"
        params.append(f.limit)

        cursor = self._conn.execute(sql, params)
        rows: list[Row] = []
        for r in cursor.fetchall():
            rows.append(
                Row(
                    id=r["id"],
                    ts=r["ts"],
                    command=r["command"],
                    burp_op=r["burp_op"],
                    target=r["target"],
                    program=r["program"],
                    tag=r["tag"],
                    status=r["status"],
                    exit_code=r["exit_code"],
                    req_sha256=r["req_sha256"],
                    resp_sha256=r["resp_sha256"],
                    resp_status=r["resp_status"],
                    resp_len=r["resp_len"],
                    duration_ms=r["duration_ms"],
                    error_code=r["error_code"],
                    req_ref=r["req_ref"],
                    resp_ref=r["resp_ref"],
                )
            )
        return rows

    # ------------------------------------------------------------------
    # tag
    # ------------------------------------------------------------------

    def tag(self, op_id: str, name: str) -> bool:
        """Set ops.tag = name WHERE id = op_id. Returns True if found."""
        cursor = self._conn.execute(
            "UPDATE ops SET tag = ? WHERE id = ?", (name, op_id)
        )
        self._conn.commit()
        return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # set_exit_code
    # ------------------------------------------------------------------

    def set_exit_code(self, op_id: str, code: int) -> bool:
        """Back-fill ops.exit_code WHERE id = op_id, once the command's final code is known.

        record() runs at HTTP time, before the CLI has resolved its exit code; cliutil.run()
        calls this afterwards so the audit row reflects the actual outcome. Returns True if found.

        ADR-0005: sqlite3.Error is caught, a one-line warning is printed to stderr,
        and False is returned so the caller can proceed without crashing.
        """
        try:
            cursor = self._conn.execute(
                "UPDATE ops SET exit_code = ? WHERE id = ?", (code, op_id)
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            import sys
            print(f"warning: ledger write failed: {exc}", file=sys.stderr)
            return False
        return cursor.rowcount > 0
