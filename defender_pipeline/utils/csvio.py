"""CSV I/O adapter — mirrors bash `csv_field()` and `csv_write_row()`.

Contract: byte-identical output vs the bash producer, so downstream
consumers (report.py, expandcsv.py) see the exact same CSV shape.

Rules (from defender.sh:40-55):

  * Every field wrapped in double quotes.
  * Internal `"` becomes `'` (bash: ``v="${v//\\"/\\'}"``).
  * Internal `\\n` and `\\r` collapse to a single space.
  * Fields joined by `,` and rows terminated by `\\n`.

This is intentionally NOT `csv.writer` from stdlib — the standard module
escapes internal `"` by doubling (`""`), which does not match the bash
producer. Diff-clean cutover requires exact reproduction.
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import Any, TextIO


def csv_field(value: Any) -> str:
    """Format a single field for CSV output — bash-compatible escaping.

    None/empty → ``""``.
    """
    s = "" if value is None else str(value)
    s = s.replace('"', "'").replace("\n", " ").replace("\r", " ")
    return f'"{s}"'


def csv_write_row(fout: TextIO, values: Sequence[Any]) -> None:
    """Write a single CSV row to `fout`.

    Fields joined by `,` and terminated by `\\n`. Every field
    round-trips through :func:`csv_field` first.
    """
    fout.write(",".join(csv_field(v) for v in values) + "\n")
