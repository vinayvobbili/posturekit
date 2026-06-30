"""Ingest: anchored header detection, dedup, and xlsx/csv schema parity."""

import duckdb
import pytest

from posturekit import ingest_table, ingest_files
from posturekit.ingest import _dedup_headers


def test_dedup_headers():
    assert _dedup_headers(["Path", "Owner", "Owner", "", "Owner"]) == \
        ["Path", "Owner", "Owner (1)", "column_3", "Owner (2)"]


def _load(path, anchor="Path"):
    con = duckdb.connect(":memory:")
    summary = ingest_table(path, "t", con, header_anchor=anchor)
    rows = con.execute('SELECT * FROM "t" ORDER BY "Path"').fetchall()
    cols = [d[0] for d in con.execute('SELECT * FROM "t" LIMIT 0').description]
    con.close()
    return summary, cols, rows


def test_xlsx_skips_banner_and_finds_header(xlsx_export):
    summary, cols, rows = _load(xlsx_export)
    assert summary["rows"] == 3
    assert cols[0] == "Path"
    # Duplicate "Owner" was disambiguated.
    assert cols.count("Owner") == 1 and "Owner (1)" in cols


def test_csv_skips_banner_and_finds_header(csv_export):
    summary, cols, rows = _load(csv_export)
    assert summary["rows"] == 3
    assert cols[0] == "Path"


def test_xlsx_csv_schema_parity(xlsx_export, csv_export):
    _, xcols, xrows = _load(xlsx_export)
    _, ccols, crows = _load(csv_export)
    assert xcols == ccols          # identical deduplicated schema
    assert xrows == crows          # identical data, both all-VARCHAR


def test_max_data_rows_caps_load(xlsx_export):
    con = duckdb.connect(":memory:")
    summary = ingest_table(xlsx_export, "t", con, header_anchor="Path", max_data_rows=1)
    assert summary["rows"] == 1
    con.close()


def test_missing_anchor_raises(csv_export):
    con = duckdb.connect(":memory:")
    with pytest.raises(RuntimeError):
        ingest_table(csv_export, "t", con, header_anchor="NoSuchColumn")
    con.close()


def test_requires_a_header_strategy(csv_export):
    con = duckdb.connect(":memory:")
    with pytest.raises(ValueError):
        ingest_table(csv_export, "t", con)  # neither anchor nor row
    con.close()


def test_ingest_files_builds_a_persistent_store(tmp_path, xlsx_export, csv_export):
    db = tmp_path / "store.duckdb"
    summaries = ingest_files({"a": xlsx_export, "b": csv_export}, db,
                             header_anchor="Path")
    assert {s["table"] for s in summaries} == {"a", "b"}
    con = duckdb.connect(str(db))
    assert con.execute('SELECT count(*) FROM "a"').fetchone()[0] == 3
    assert con.execute('SELECT count(*) FROM "b"').fetchone()[0] == 3
    con.close()
