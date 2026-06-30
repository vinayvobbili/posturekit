# posturekit

Ingest large, messy data-security exports and score them for risk — a
model-agnostic [DSPM](https://en.wikipedia.org/wiki/Data_security_posture_management)
kernel. Bring your own data and your own risk matrix.

Two building blocks, usable together or apart:

- **`ingest`** — load big, ugly tabular exports (`.xlsx` / `.csv`) into
  [DuckDB](https://duckdb.org) in constant memory. Survives the things that
  break naive readers: a multi-GB inner sheet XML with a **bogus `<dimension>`**,
  inline strings, a report **banner above the header**, and **duplicate column
  names** in denormalised exports. Header rows are found by *anchor column*, so
  you don't hardcode a row number.
- **`scoring`** — a **pure, config-driven** engine that turns per-resource
  signals (exposure × sensitive-data × retention) into a risk score, level,
  SLA and remediation action. No I/O, no model calls — fully unit-testable and
  reusable across any resource type (mailboxes, folders, sites, drives, shares).

## Install

    pip install posturekit            # scoring engine only (zero deps)
    pip install "posturekit[ingest]"  # + DuckDB / pyarrow / lxml ingest stack

## Score resources

```python
from posturekit import score_resource

profile = score_resource({
    "exposure_level": "anyone",
    "classifications": ["credentials", "pii"],
    "sensitive_hit_count": 4200,
    "age_years": 9,
})
# profile["risk_level"]            -> "Critical"
# profile["remediation_priority"] -> "P1"
# profile["sla_days"]             -> 7
# profile["recommended_action"]   -> "Permission Removal"
# profile["risk_combinations"]    -> ["sensitive_stale_and_broad", ...]
```

The whole model — weights, exposure scale, sensitive-class ceilings, retention
buckets, combination boosts, score→level bands, SLAs — lives in one `CONFIG`
dict, and every function takes a `config=` override. Drop in your own risk
matrix without touching the code:

```python
score_resource(signals, config={"bands": [
    {"min_score": 70, "level": "Critical", "priority": "P1", "sla_days": 3},
    {"min_score": 0,  "level": "Low",      "priority": "P4", "sla_days": 180},
]})
```

## Ingest an export

```python
import duckdb
from posturekit import ingest_table

con = duckdb.connect("posture.duckdb")
ingest_table("Resources.xlsx", "resources", con, header_anchor="Path")
ingest_table("Permissions.csv", "permissions", con, header_anchor="Path")
```

Every column lands as `VARCHAR` (lossless — cast/derive at query time). The
`.xlsx` and `.csv` paths produce an **identical schema** for the same export, so
your downstream SQL doesn't care which format the data arrived in. For an export
whose layout you know exactly, pass `header_row=12` instead of `header_anchor`.

## End to end

```python
from posturekit import score_batch, summarize

cur = con.execute('SELECT * FROM "resources"')
cols = [c[0] for c in cur.description]
rows = [dict(zip(cols, r)) for r in cur.fetchall()]

scored = score_batch(to_signals(r) for r in rows)   # you map columns -> signals
print(summarize(scored))
# {'total': ..., 'by_level': {'Critical': ...}, 'by_combination': {...}}
```

See [`examples/demo.py`](examples/demo.py) for a runnable build→ingest→score→summarize.

## License

MIT
