"""Shared fixtures: synthetic exports built to mimic real-world warts.

We build a tiny .xlsx by hand (zip + minimal sheet XML using inline strings and a
deliberately *bogus* <dimension>, exactly the shape that defeats openpyxl's
read-only mode) and a matching .csv with a report banner above the header. Both
carry a duplicate column name so we exercise header deduplication, and both share
the same anchor column ("Path") so the anchored header detection is tested on
each format.
"""

import io
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

import pytest

# Header row carries an anchor column "Path" plus a duplicate "Owner".
HEADER = ["Path", "Resource type", "Exposure level", "Owner", "Owner"]
DATA_ROWS = [
    ["mbx/ceo", "Mailbox", "anyone", "ceo@example", "exec"],
    ["fld/finance", "Folder", "org_wide", "cfo@example", "finance"],
    ["mbx/intern", "Mailbox", "internal", "intern@example", "ops"],
]
# Two banner rows sit above the header in both exports.
BANNER = ["Acme DSPM Export — generated 2026-06-30", "Confidential"]


def _cell_xml(col_letter, rownum, value):
    if value is None or value == "":
        return ""
    return (f'<c r="{col_letter}{rownum}" t="inlineStr">'
            f'<is><t>{escape(str(value))}</t></is></c>')


def _col_letter(idx):
    # 0 -> A, 1 -> B ...
    s = ""
    idx += 1
    while idx:
        idx, rem = divmod(idx - 1, 26)
        s = chr(65 + rem) + s
    return s


def _build_xlsx(path):
    """Write a minimal .xlsx with banner + header + data, all inline strings."""
    grid = [[b] for b in BANNER] + [HEADER] + DATA_ROWS  # banner cells in col A
    rows_xml = []
    for r, row in enumerate(grid, start=1):
        cells = "".join(_cell_xml(_col_letter(c), r, v) for c, v in enumerate(row))
        rows_xml.append(f'<row r="{r}">{cells}</row>')
    # Bogus dimension — claims only A1:A1, which is exactly the trap.
    sheet = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<dimension ref="A1:A1"/>'
        f'<sheetData>{"".join(rows_xml)}</sheetData></worksheet>'
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        '</Types>'
    )
    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/></sheets>'
        '</workbook>'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("xl/workbook.xml", workbook)
        zf.writestr("xl/worksheets/sheet1.xml", sheet)
    Path(path).write_bytes(buf.getvalue())


def _build_csv(path):
    """Write a matching .csv: two banner lines, then header, then data."""
    import csv
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        for b in BANNER:
            w.writerow([b])
        w.writerow(HEADER)
        for row in DATA_ROWS:
            w.writerow(row)


@pytest.fixture
def xlsx_export(tmp_path):
    p = tmp_path / "export.xlsx"
    _build_xlsx(p)
    return p


@pytest.fixture
def csv_export(tmp_path):
    p = tmp_path / "export.csv"
    _build_csv(p)
    return p
