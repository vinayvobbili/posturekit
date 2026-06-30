"""Streaming reader for very large / malformed .xlsx exports.

Reads a single worksheet row-by-row straight from the inner sheet XML, in
constant memory, *without* trusting the workbook's declared ``<dimension>``.
Some exporters write a bogus dimension that makes both openpyxl's read-only
mode and DuckDB's ``read_xlsx`` stop after a handful of rows — yet the sheet
really holds ~1M rows in a multi-GB inner XML that uses inline strings. This
reader walks every ``<row>`` element via ``lxml.iterparse`` and clears each one
after use, so memory stays flat no matter how large the sheet.

Handles the three cell encodings that appear in practice: inline strings
(``t="inlineStr"``), shared strings (``t="s"`` indexing sharedStrings.xml) and
bare numeric / ISO-date cells. Each row is yielded with its true 1-based
spreadsheet row number (from the ``r`` attribute) so callers can locate a header
row precisely even when empty rows above it are omitted from the XML.
"""

import zipfile

from lxml import etree

_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"


def col_index(ref: str) -> int:
    """'AB12' -> 27 (0-based column index). Stops at the first digit."""
    n = 0
    for ch in ref:
        if ch.isalpha():
            n = n * 26 + (ord(ch.upper()) - 64)
        else:
            break
    return n - 1


def _shared_strings(zf: zipfile.ZipFile):
    try:
        data = zf.read("xl/sharedStrings.xml")
    except KeyError:
        return []
    root = etree.fromstring(data)
    return ["".join(t.text or "" for t in si.iter(f"{_NS}t")) for si in root]


def stream_sheet(path: str, sheet_path: str = "xl/worksheets/sheet1.xml"):
    """Yield ``(row_number, [cell, ...])`` for every row in the sheet.

    ``row_number`` is the 1-based spreadsheet row (int). The cell list is
    densified to the row's own max populated column (callers normalise width).
    Cell values are returned as ``str`` (or ``None`` for empty cells).
    """
    zf = zipfile.ZipFile(path)
    shared = _shared_strings(zf)
    seq = 0
    try:
        with zf.open(sheet_path) as fh:
            for _, row_el in etree.iterparse(fh, events=("end",), tag=f"{_NS}row"):
                seq += 1
                r_attr = row_el.get("r")
                rownum = int(r_attr) if r_attr and r_attr.isdigit() else seq
                cells = {}
                maxc = -1
                for c in row_el:
                    ref = c.get("r") or ""
                    ci = col_index(ref) if ref and ref[0].isalpha() else maxc + 1
                    t = c.get("t")
                    val = None
                    if t == "inlineStr":
                        is_el = c.find(f"{_NS}is")
                        if is_el is not None:
                            val = "".join(tt.text or "" for tt in is_el.iter(f"{_NS}t"))
                    elif t == "s":
                        v = c.find(f"{_NS}v")
                        if v is not None and v.text is not None:
                            try:
                                val = shared[int(v.text)]
                            except (ValueError, IndexError):
                                val = None
                    else:
                        v = c.find(f"{_NS}v")
                        val = v.text if v is not None else None
                    cells[ci] = val
                    if ci > maxc:
                        maxc = ci
                yield rownum, [cells.get(i) for i in range(maxc + 1)]
                # Free the parsed row and any siblings lxml is holding onto.
                row_el.clear()
                parent = row_el.getparent()
                if parent is not None:
                    while row_el.getprevious() is not None:
                        del parent[0]
    finally:
        zf.close()
