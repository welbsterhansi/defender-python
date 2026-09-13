"""defender_pipeline — Python API-first re-implementation of the bash pipeline.

Runs in parallel to the existing bash pipeline (`defender.sh`,
`enrich_cvedetails.py`, `check_ocp.sh`, `expandcsv.py`, `report.py`)
during the P0.4–P0.7 migration. Uses Azure SDKs and the Kubernetes
Python client directly — no `az`/`az rest`/`az acr`/`oc` subprocess
in the main path.

See:
    docs/python-architecture.md   — design decisions
    docs/contracts/               — frozen output contracts

Public entry point: ``python -m defender_pipeline`` (see ``cli.py``).
"""
from __future__ import annotations

__version__ = "0.1.0"
