"""Unified and Structured Diff Generation."""

import difflib
from typing import Any, Dict, List


def generate_unified_diff(original: str, modified: str, filename: str = "file.py") -> str:
    """Generate standard unified diff format string."""
    orig_lines = original.splitlines(keepends=True)
    mod_lines = modified.splitlines(keepends=True)

    diff_lines = list(
        difflib.unified_diff(
            orig_lines,
            mod_lines,
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
            n=3,
        )
    )
    return "".join(diff_lines)


def generate_diff_chunks(original: str, modified: str, filename: str = "file.py") -> Dict[str, Any]:
    """Generate structured line-by-line diff metadata suitable for JSON API and rich UI diff rendering.

    Returns dictionary containing:
        - unified_diff: str
        - original_lines: list of str
        - modified_lines: list of str
        - additions: int
        - deletions: int
        - lines: list of dicts with {type: 'add'|'del'|'context', text: str, old_no: int, new_no: int}
    """
    orig_lines = original.splitlines()
    mod_lines = modified.splitlines()

    matcher = difflib.SequenceMatcher(None, orig_lines, mod_lines)
    diff_entries: List[Dict[str, Any]] = []
    additions = 0
    deletions = 0

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for offset in range(i2 - i1):
                diff_entries.append({
                    "type": "context",
                    "text": orig_lines[i1 + offset],
                    "old_line": i1 + offset + 1,
                    "new_line": j1 + offset + 1,
                })
        elif tag == "delete":
            for offset in range(i2 - i1):
                deletions += 1
                diff_entries.append({
                    "type": "delete",
                    "text": orig_lines[i1 + offset],
                    "old_line": i1 + offset + 1,
                    "new_line": None,
                })
        elif tag == "insert":
            for offset in range(j2 - j1):
                additions += 1
                diff_entries.append({
                    "type": "insert",
                    "text": mod_lines[j1 + offset],
                    "old_line": None,
                    "new_line": j1 + offset + 1,
                })
        elif tag == "replace":
            for offset in range(i2 - i1):
                deletions += 1
                diff_entries.append({
                    "type": "delete",
                    "text": orig_lines[i1 + offset],
                    "old_line": i1 + offset + 1,
                    "new_line": None,
                })
            for offset in range(j2 - j1):
                additions += 1
                diff_entries.append({
                    "type": "insert",
                    "text": mod_lines[j1 + offset],
                    "old_line": None,
                    "new_line": j1 + offset + 1,
                })

    return {
        "filename": filename,
        "unified_diff": generate_unified_diff(original, modified, filename),
        "additions": additions,
        "deletions": deletions,
        "lines": diff_entries,
        "original_code": original,
        "modified_code": modified,
    }
