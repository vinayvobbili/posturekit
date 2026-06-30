"""Load large, messy tabular exports (.xlsx / .csv) into DuckDB.

Real-world security and inventory exports are awkward: multi-GB inner XML with a
malformed ``<dimension>`` tag, inline strings, a report preamble above the real
header row, and duplicate column names (a denormalised export lays resource +
permission + account attributes side by side). This module streams such a file
in constant memory and loads it into a persistent DuckDB store, one table per
file, every column kept as VARCHAR (lossless — you cast / derive at query time).
Duplicate headers are disambiguated with a numeric suffix so they survive as
distinct columns.

The header row is located one of two ways:

* ``header_anchor="path"`` — scan the first rows for the row that contains a cell
  equal to the anchor (case-insensitive) and has at least ``min_header_cells``
  non-empty cells. Works for both .xlsx and .csv, and tolerates a report banner
  of unknown height above the header.
* ``header_row=12`` — the header is on a fixed 1-based spreadsheet row (.xlsx
  only; cheaper when you know the export's exact layout).

The ``.csv`` path uses DuckDB's native reader (no row ceiling, much faster than
the streaming-XML path); ``.xlsx`` uses :func:`posturekit.xlsx_stream.stream_sheet`.
Both yield the same all-VARCHAR schema with the same deduplicated header names,
so every downstream query is identical regardless of source format.
"""

import csv as _csv
import logging
import time
from pathlib import Path

import duckdb
import pyarrow as pa

from .xlsx_stream import stream_sheet

logger = logging.getLogger(__name__)

# How many leading rows to scan when looking for an anchored header row.
HEADER_SCAN = 200
# Minimum non-empty cells a candidate header row must have (rejects banner lines).
MIN_HEADER_CELLS = 4


def _dedup_headers(raw):
    """Clean + uniquify header names so duplicates become distinct columns."""
    seen = {}
    out = []
    for i, h in enumerate(raw):
        name = (h or "").strip()
        if not name:
            name = f"column_{i}"
        if name in seen:
            seen[name] += 1
            name = f"{name} ({seen[name]})"
        else:
            seen[name] = 0
        out.append(name)
    return out


def ingest_table(path, table, con, *, header_anchor=None, header_row=None,
                 batch_size=20000, max_data_rows=None, progress_every=100000,
                 min_header_cells=MIN_HEADER_CELLS, header_scan=HEADER_SCAN):
    """Load one export into ``table``. Dispatches on file type.

    Provide exactly one of ``header_anchor`` (scan for a header row containing
    that column name) or ``header_row`` (a fixed 1-based .xlsx row). ``.csv``
    files require ``header_anchor``.
    """
    if header_anchor is None and header_row is None:
        raise ValueError("provide header_anchor= or header_row=")
    if str(path).lower().endswith(".csv"):
        if header_anchor is None:
            raise ValueError("CSV ingest requires header_anchor=")
        return _ingest_csv(path, table, con, header_anchor,
                           max_data_rows=max_data_rows,
                           min_header_cells=min_header_cells, header_scan=header_scan)
    return _ingest_xlsx(path, table, con, header_anchor=header_anchor,
                        header_row=header_row, batch_size=batch_size,
                        max_data_rows=max_data_rows, progress_every=progress_every,
                        min_header_cells=min_header_cells, header_scan=header_scan)


def _resolve_xlsx_header(rows_iter, header_anchor, header_row, min_header_cells,
                         header_scan, table):
    """Return (header_names, last_header_rownum) by anchor scan or fixed row."""
    anchor = (header_anchor or "").strip().lower()
    for rownum, row in rows_iter:
        if header_row is not None:
            if rownum == header_row:
                return _dedup_headers(row), rownum
            if rownum > header_row:
                raise RuntimeError(f"{table}: no header found at row {header_row}")
            continue
        # anchor scan
        cells = [(c or "").strip().lower() for c in row]
        nonempty = [c for c in cells if c]
        if anchor in cells and len(nonempty) >= min_header_cells:
            return _dedup_headers([(c or "").strip() for c in row]), rownum
        if rownum > header_scan:
            raise RuntimeError(
                f"{table}: no header row with a '{header_anchor}' column in the "
                f"first {header_scan} rows")
    raise RuntimeError(f"{table}: reached EOF before locating the header row")


def _ingest_xlsx(path, table, con, *, header_anchor, header_row, batch_size,
                 max_data_rows, progress_every, min_header_cells, header_scan):
    """Stream one .xlsx file into ``table``. Returns a summary dict."""
    rows = stream_sheet(str(path))
    header, header_rownum = _resolve_xlsx_header(
        rows, header_anchor, header_row, min_header_cells, header_scan, table)

    ncol = len(header)
    cols_ddl = ", ".join(f'"{c}" VARCHAR' for c in header)
    con.execute(f'DROP TABLE IF EXISTS "{table}"')
    con.execute(f'CREATE TABLE "{table}" ({cols_ddl})')

    # Columnar buffers + Arrow insert: ~6x faster than executemany at this scale.
    buffers = [[] for _ in range(ncol)]
    n = 0
    t0 = time.time()

    def flush():
        if not buffers[0]:
            return
        batch_tbl = pa.table({f"c{i}": pa.array(buffers[i], type=pa.string())
                              for i in range(ncol)})
        con.execute('INSERT INTO "%s" SELECT * FROM batch_tbl' % table)
        for col in buffers:
            col.clear()

    for rownum, row in rows:  # continues past the header row
        if rownum <= header_rownum:
            continue
        if len(row) < ncol:
            row = row + [None] * (ncol - len(row))
        elif len(row) > ncol:
            row = row[:ncol]
        for i in range(ncol):
            buffers[i].append(row[i])
        n += 1
        if len(buffers[0]) >= batch_size:
            flush()
        if n % progress_every == 0:
            rate = n / (time.time() - t0)
            logger.info("ingest %s: %s rows (%.0f r/s)", table, f"{n:,}", rate)
        if max_data_rows and n >= max_data_rows:
            break
    flush()
    con.execute("CHECKPOINT")
    secs = round(time.time() - t0, 1)
    logger.info("ingest %s done: %s rows x %s cols in %ss", table, f"{n:,}", ncol, secs)
    return {"table": table, "rows": n, "cols": ncol, "seconds": secs, "header": header}


# ---------------------------------------------------------------------------
# CSV path — for exports that exceed the .xlsx ~1.05M-row ceiling.
# ---------------------------------------------------------------------------

def _detect_csv_header(path, header_anchor, min_header_cells=MIN_HEADER_CELLS,
                       max_scan=HEADER_SCAN):
    """Locate the header row in a CSV export.

    Returns ``(skip, delimiter, names)`` where ``skip`` is the number of rows
    before the header, ``delimiter`` is the detected field separator, and
    ``names`` are the deduplicated column names (same scheme as the .xlsx path,
    so the resulting schema matches exactly).
    """
    anchor = (header_anchor or "").strip().lower()
    for delim in (",", ";", "\t"):
        try:
            with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as fh:
                reader = _csv.reader(fh, delimiter=delim)
                for idx, row in enumerate(reader):
                    if idx > max_scan:
                        break
                    cells = [(c or "").strip().strip('"').lower() for c in row]
                    nonempty = [c for c in cells if c]
                    if anchor in cells and len(nonempty) >= min_header_cells:
                        names = _dedup_headers([(c or "").strip().strip('"') for c in row])
                        return idx, delim, names
        except Exception:
            continue
    raise RuntimeError(f"{Path(path).name}: could not find a header row — no "
                       f"'{header_anchor}' column in the first {max_scan} rows")


def _ingest_csv(path, table, con, header_anchor, max_data_rows=None,
                min_header_cells=MIN_HEADER_CELLS, header_scan=HEADER_SCAN):
    """Load one .csv export into ``table`` via DuckDB's native reader."""
    t0 = time.time()
    skip, delim, names = _detect_csv_header(
        path, header_anchor, min_header_cells=min_header_cells, max_scan=header_scan)
    ncol = len(names)

    path_lit = str(path).replace("'", "''")
    delim_lit = {",": ",", ";": ";", "\t": "\\t"}[delim]
    names_lit = "[" + ", ".join("'" + n.replace("'", "''") + "'" for n in names) + "]"
    limit = f" LIMIT {int(max_data_rows)}" if max_data_rows else ""

    con.execute(f'DROP TABLE IF EXISTS "{table}"')
    con.execute(
        f'CREATE TABLE "{table}" AS SELECT * FROM read_csv(\'{path_lit}\', '
        f"delim='{delim_lit}', skip={int(skip)}, header=true, all_varchar=true, "
        f"names={names_lit}, quote='\"', escape='\"', "
        f"null_padding=true, ignore_errors=true, max_line_size=10000000){limit}"
    )
    con.execute("CHECKPOINT")
    n = con.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0]
    secs = round(time.time() - t0, 1)
    logger.info("ingest %s (csv) done: %s rows x %s cols in %ss",
                table, f"{n:,}", ncol, secs)
    return {"table": table, "rows": n, "cols": ncol, "seconds": secs, "header": names}


def ingest_files(file_map, db_path, *, header_anchor=None, header_row=None):
    """Ingest an explicit ``{table: path}`` map (any mix of .xlsx / .csv).

    ``db_path`` is the DuckDB store to (re)build. The same ``header_anchor`` /
    ``header_row`` applies to every file in the map; load files with differing
    layouts in separate calls.
    """
    target = Path(db_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(target))
    summaries = []
    try:
        for table, path in file_map.items():
            p = Path(path)
            if not p.exists():
                raise FileNotFoundError(p)
            logger.info("ingest: loading %s -> %s", p.name, table)
            summaries.append(ingest_table(p, table, con, header_anchor=header_anchor,
                                          header_row=header_row))
    finally:
        con.close()
    return summaries
