"""
Parse dataset/Tag Definitions.md into authoritative Python dicts.

Outputs:
    TAGS    — {tag_title: {"description": str, "knowledge_url": str | None, "subtags": list[str]}}
    SUBTAGS — {subtag_title: {"description": str}}
"""

import re
from pathlib import Path


_MD_PATH = Path(__file__).parent.parent / "dataset" / "Tag Definitions.md"


def _strip_md(text: str) -> str:
    """Remove bold markers and collapse whitespace."""
    text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)
    return " ".join(text.split())


def _extract_knowledge_url(cell: str) -> str | None:
    """Pull the href out of a markdown link like [📚](url), or return None."""
    m = re.search(r"\[.+?\]\((.+?)\)", cell)
    return m.group(1) if m else None


def _parse_subtag_list(cell: str) -> list[str]:
    """Extract backtick-quoted subtag names from a table cell."""
    return re.findall(r"`([^`]+)`", cell)


def _split_row(row: str) -> list[str]:
    """Split a markdown table row on '|', strip surrounding whitespace."""
    parts = row.strip().strip("|").split("|")
    return [p.strip() for p in parts]


def _is_separator(row: str) -> bool:
    return bool(re.fullmatch(r"[\|\s\-:]+", row))


def _parse_table_rows(lines: list[str], n_cols: int) -> list[list[str]]:
    """
    Parse a markdown table into a list of column lists, handling two split cases:

    Case 1 — mid-cell newline, continuation does NOT start with '|':
        | Title | desc part 1
        desc part 2 | url | subtags |

    Case 2 — row split across two '|'-prefixed lines (e.g. DoS in Tag Definitions):
        | DoS | desc part 1 |          ← only 2 data cols
        | desc part 2 | url | subtags | ← remaining 3 data cols

    In case 2 we detect the short row (< n_cols columns) and merge the next
    row's first column into the current row's last column.
    """
    result: list[list[str]] = []
    pending: list[str] | None = None

    for line in lines:
        if not line.strip():
            continue

        if not line.startswith("|"):
            # Case 1 plain continuation
            if pending is not None:
                pending[-1] += " " + line.strip()
            elif result:
                result[-1][-1] += " " + line.strip()
            continue

        if _is_separator(line):
            continue

        cols = _split_row(line)

        if pending is not None:
            # Case 2: merge — this line's first col continues pending's last col
            pending[-1] += " " + cols[0]
            pending.extend(cols[1:])
            if len(pending) >= n_cols:
                result.append(pending)
                pending = None
            # else keep accumulating (shouldn't happen in practice)
        elif len(cols) < n_cols:
            # Short row — hold it until we see the next line
            pending = cols
        else:
            result.append(cols)

    return result


def parse(path: Path = _MD_PATH) -> tuple[dict, dict]:
    raw = path.read_text(encoding="utf-8")
    lines = raw.splitlines()

    # ── locate section boundaries ────────────────────────────────────────────
    tag_header_idx = next(
        i for i, l in enumerate(lines) if "**Title**" in l and "**Knowledge**" in l
    )
    subtag_header_idx = next(
        i for i, l in enumerate(lines)
        if "**Title**" in l and "**Knowledge**" not in l and i > tag_header_idx
    )

    tag_lines    = lines[tag_header_idx + 2 : subtag_header_idx]   # skip header + separator
    subtag_lines = lines[subtag_header_idx + 2 :]                  # skip header + separator

    # ── parse Tags table  (4 cols: title | description | knowledge | subtags) ─
    tags: dict = {}
    for cols in _parse_table_rows(tag_lines, n_cols=4):
        title       = _strip_md(cols[0])
        description = _strip_md(cols[1])
        knowledge   = _extract_knowledge_url(cols[2])
        subtag_list = _parse_subtag_list(cols[3])
        if title:
            tags[title] = {
                "description":   description,
                "knowledge_url": knowledge,
                "subtags":       subtag_list,
            }

    # ── parse Subtags table  (2 cols: title | description) ───────────────────
    subtags: dict = {}
    for cols in _parse_table_rows(subtag_lines, n_cols=2):
        title       = _strip_md(cols[0])
        description = _strip_md(cols[1])
        if title:
            subtags[title] = {"description": description}

    return tags, subtags


TAGS, SUBTAGS = parse()


if __name__ == "__main__":
    print(f"Tags   : {len(TAGS)}")
    print(f"Subtags: {len(SUBTAGS)}")

    missing = {
        sub
        for info in TAGS.values()
        for sub in info["subtags"]
        if sub not in SUBTAGS
    }
    if missing:
        print("WARNING — subtag references with no definition:")
        for m in sorted(missing):
            print(f"  {m!r}")
    else:
        print("Taxonomy check passed: all subtag references resolve correctly.")
