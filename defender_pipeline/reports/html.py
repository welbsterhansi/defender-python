"""HTML report generation.

Rather than porting ``report.py`` line-by-line, the P0.7 plan is to
invoke it as an ``import`` (not subprocess) from a thin wrapper here.
This keeps the report code untouched while giving us a single CLI
entry point in the new package.

Implemented in task P0.7.
"""
from __future__ import annotations
