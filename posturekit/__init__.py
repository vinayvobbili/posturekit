"""posturekit — ingest messy data-security exports and score them for risk.

Two model-agnostic building blocks for a Data Security Posture (DSPM) pipeline:

* ``ingest`` — load large / malformed tabular exports (.xlsx, .csv) into DuckDB
  in constant memory, with anchor-based header detection and duplicate-column
  handling.
* ``scoring`` — a pure, config-driven engine that turns per-resource exposure /
  sensitive / retention signals into a risk score, level, SLA and action.

Nothing here knows about any specific vendor, tenant, or data store.
"""

from .scoring import (  # noqa: F401
    CONFIG,
    exposure_score,
    sensitive_score,
    retention_score,
    retention_bucket,
    score_resource,
    score_batch,
    summarize,
)

# The ingest stack (DuckDB / pyarrow / lxml) is an optional extra: the pure
# scoring engine above must import even where those heavy deps aren't installed.
try:
    from .ingest import ingest_table, ingest_files  # noqa: F401
    from .xlsx_stream import stream_sheet, col_index  # noqa: F401
except ImportError:  # pragma: no cover - exercised only on a scoring-only install
    ingest_table = ingest_files = stream_sheet = col_index = None

__version__ = "0.1.0"

__all__ = [
    "ingest_table",
    "ingest_files",
    "stream_sheet",
    "col_index",
    "CONFIG",
    "exposure_score",
    "sensitive_score",
    "retention_score",
    "retention_bucket",
    "score_resource",
    "score_batch",
    "summarize",
    "__version__",
]
