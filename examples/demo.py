"""End-to-end: build a synthetic export, ingest it, score every row, summarize.

Run it:  python examples/demo.py

Writes a throwaway .csv export with a report banner above the header, loads it
into an in-memory DuckDB table via posturekit.ingest, projects each row into the
canonical signal shape, scores the batch, and prints the risk distribution.
Nothing here is tied to any vendor or tenant.
"""

import csv
import tempfile
from pathlib import Path

import duckdb

from posturekit import ingest_table, score_batch, summarize

HEADER = ["Path", "Resource type", "Exposure level", "Classification",
          "Sensitive hits", "Age (years)"]
ROWS = [
    ["mbx/ceo", "Mailbox", "anyone", "credentials,pii", "4200", "9"],
    ["fld/finance", "Folder", "org_wide", "financial", "75", "2"],
    ["fld/hr-archive", "Folder", "internal", "pii", "30", "7"],
    ["mbx/intern", "Mailbox", "internal", "", "0", "1"],
    ["mbx/owner-only", "Mailbox", "owner_only", "", "0", "0.4"],
]


def build_export(path):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["Acme DSPM Export — generated 2026-06-30"])  # banner
        w.writerow(["CONFIDENTIAL"])                              # banner
        w.writerow(HEADER)
        w.writerows(ROWS)


def row_to_signals(r):
    """Project an ingested table row into the canonical scoring signal shape."""
    classes = [c.strip() for c in (r["Classification"] or "").split(",") if c.strip()]
    return {
        "name": r["Path"],
        "exposure_level": r["Exposure level"],
        "classifications": classes,
        "sensitive_hit_count": int(r["Sensitive hits"] or 0),
        "age_years": float(r["Age (years)"] or 0),
    }


def main():
    with tempfile.TemporaryDirectory() as d:
        export = Path(d) / "export.csv"
        build_export(export)

        con = duckdb.connect(":memory:")
        summary = ingest_table(export, "resources", con, header_anchor="Path")
        print(f"ingested {summary['rows']} rows x {summary['cols']} cols "
              f"(header found below the banner)\n")

        cur = con.execute('SELECT * FROM "resources"')
        cols = [c[0] for c in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        con.close()

        scored = score_batch(row_to_signals(r) for r in rows)
        for s in sorted(scored, key=lambda x: -x["risk_score"]):
            print(f"{s['name']:18s} {s['risk_level']:8s} "
                  f"score={s['risk_score']:5.1f} "
                  f"(E{s['exposure_score']:.0f}/S{s['sensitive_score']:.0f}/R{s['retention_score']:.0f}) "
                  f"sla={s['sla_days']:>3}d  {s['recommended_action']}")

        print("\nsummary:", summarize(scored))


if __name__ == "__main__":
    main()
