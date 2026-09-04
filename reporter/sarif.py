"""SARIF (Static Analysis Results Interchange Format) v2.1.0 reporter for LeakGuard."""

import json
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional, TextIO

from models.report import AnalysisReport
from models.issue import LeakIssue, Severity
from models.baseline import normalize_path


_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_SARIF_VERSION = "2.1.0"

_SEVERITY_TO_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_RULES_CATALOG: Dict[str, Dict[str, Any]] = {
    "LEAK001": {
        "id": "LEAK001",
        "name": "UnclosedFileDescriptor",
        "shortDescription": {"text": "Unclosed file descriptor leak detected."},
        "fullDescription": {
            "text": "A file resource opened via open() was not reliably closed on all execution paths."
        },
        "defaultConfiguration": {"level": "error"},
        "help": {
            "text": "Ensure file handles are closed via try...finally or managed with a 'with' context manager."
        },
    },
    "LEAK002": {
        "id": "LEAK002",
        "name": "UnclosedSqliteConnection",
        "shortDescription": {"text": "Unclosed SQLite connection leak detected."},
        "fullDescription": {
            "text": "A sqlite3 database connection was opened but not properly closed, potentially leaking locks and memory."
        },
        "defaultConfiguration": {"level": "error"},
        "help": {
            "text": "Ensure sqlite3.connect() handles are explicitly closed in a finally block or with contextlib.closing."
        },
    },
}


class SARIFReporter:
    """Formats analysis report into standard OASIS SARIF v2.1.0 JSON format."""

    def __init__(self, stream: Optional[TextIO] = None, indent: int = 2) -> None:
        self.stream = stream or sys.stdout
        self.indent = indent

    def to_sarif_dict(self, report: AnalysisReport) -> Dict[str, Any]:
        """Convert report to OASIS SARIF v2.1.0 dictionary."""
        results: List[Dict[str, Any]] = []

        for issue in report.issues:
            sev = issue.severity
            if isinstance(sev, str):
                try:
                    sev = Severity(sev.upper())
                except ValueError:
                    sev = Severity.HIGH

            level = _SEVERITY_TO_SARIF_LEVEL.get(sev, "error")
            rule_id = issue.rule_id or "LEAK001"
            raw_path = issue.location.file_path if issue.location else ""
            norm_uri = normalize_path(raw_path, base_dir=report.target_path)
            start_line = issue.location.line if issue.location and issue.location.line > 0 else 1
            start_col = issue.location.column if issue.location and issue.location.column and issue.location.column > 0 else 1

            result_item: Dict[str, Any] = {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": issue.message or issue.problem or "Resource leak detected."
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": norm_uri,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": start_line,
                                "startColumn": start_col,
                            },
                        }
                    }
                ],
                "properties": {
                    "resource_name": issue.resource_name or issue.variable or "",
                    "resource_type": issue.resource_type or "file",
                    "recommendation": issue.recommendation or "",
                    "leak_path": issue.leak_path or "",
                    "severity": getattr(sev, "value", str(sev)),
                },
            }
            results.append(result_item)

        # Include any syntax errors as SARIF results
        for err in report.syntax_errors:
            err_uri = normalize_path(err.filename, base_dir=report.target_path)
            err_line = err.line if err.line and err.line > 0 else 1
            err_col = err.column if err.column and err.column > 0 else 1
            results.append({
                "ruleId": "SYNTAX001",
                "level": "error",
                "message": {"text": f"Syntax Error: {err.message}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": err_uri,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": err_line,
                                "startColumn": err_col,
                            },
                        }
                    }
                ],
                "properties": {
                    "text": err.text or "",
                },
            })

        rules_list = list(_RULES_CATALOG.values())
        if report.syntax_errors:
            rules_list.append({
                "id": "SYNTAX001",
                "name": "PythonSyntaxError",
                "shortDescription": {"text": "Python syntax error prevents static AST parsing."},
                "defaultConfiguration": {"level": "error"},
            })

        sarif: Dict[str, Any] = {
            "$schema": _SARIF_SCHEMA,
            "version": _SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "LeakGuard",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/leakguard/leakguard",
                            "rules": rules_list,
                        }
                    },
                    "results": results,
                }
            ],
        }
        return sarif

    def to_sarif(self, report: AnalysisReport) -> str:
        """Convert report to formatted SARIF JSON string."""
        return json.dumps(self.to_sarif_dict(report), indent=self.indent)

    def report(self, report: AnalysisReport) -> None:
        """Write SARIF output to stream."""
        self.stream.write(self.to_sarif(report))
        self.stream.write("\n")
