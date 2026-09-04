"""Automated Benchmark Runner for LeakGuard Python Test Corpus.

Executes LeakGuard's AnalysisEngine on the 12 canonical test corpus files:
- 6 Intentional leaks (File & SQLite)
- 5 Safe patterns (File & SQLite)
- 1 Syntax error case

Calculates True Positives, False Positives, False Negatives, True Negatives,
Precision, Recall, F1 Score, and Accuracy from actual execution.
Outputs structured JSON to benchmark/results.json and prints an actionable CLI table.
"""

import json
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure project root is in sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from analyzer.engine import AnalysisEngine


@dataclass
class CorpusTestCase:
    """Specification of a test corpus file and expected behavior."""

    rel_path: str
    category: str  # "leak", "safe", "syntax"
    resource_type: Optional[str]  # "file", "SQLite connection", None
    expected_status: str  # "LEAK", "SAFE", "SYNTAX_ERROR"
    description: str


# Canonical 12-file test corpus definitions
CANONICAL_CORPUS: List[CorpusTestCase] = [
    # 6 Intentional Leaks
    CorpusTestCase(
        rel_path="python/leaks/file_no_close.py",
        category="leak",
        resource_type="file",
        expected_status="LEAK",
        description="Sequential file open and return without close()",
    ),
    CorpusTestCase(
        rel_path="python/leaks/early_return.py",
        category="leak",
        resource_type="file",
        expected_status="LEAK",
        description="File open with early return in if branch before close()",
    ),
    CorpusTestCase(
        rel_path="python/leaks/exception_leak.py",
        category="leak",
        resource_type="file",
        expected_status="LEAK",
        description="File open with unclosed return inside except handler",
    ),
    CorpusTestCase(
        rel_path="python/leaks/raise_leak.py",
        category="leak",
        resource_type="file",
        expected_status="LEAK",
        description="File open with unhandled raise before close()",
    ),
    CorpusTestCase(
        rel_path="python/leaks/sqlite_leak.py",
        category="leak",
        resource_type="SQLite connection",
        expected_status="LEAK",
        description="sqlite3.connect() allocated without close()",
    ),
    CorpusTestCase(
        rel_path="python/leaks/sqlite_early_return.py",
        category="leak",
        resource_type="SQLite connection",
        expected_status="LEAK",
        description="sqlite3.connect() with early return in if branch",
    ),
    # 5 Safe Patterns
    CorpusTestCase(
        rel_path="python/safe/explicit_close.py",
        category="safe",
        resource_type="file",
        expected_status="SAFE",
        description="Sequential file open and guaranteed f.close()",
    ),
    CorpusTestCase(
        rel_path="python/safe/with_file.py",
        category="safe",
        resource_type="file",
        expected_status="SAFE",
        description="File context manager with open(...) as f:",
    ),
    CorpusTestCase(
        rel_path="python/safe/finally_close.py",
        category="safe",
        resource_type="file",
        expected_status="SAFE",
        description="Guaranteed f.close() inside finally: block",
    ),
    CorpusTestCase(
        rel_path="python/safe/exception_finally.py",
        category="safe",
        resource_type="file",
        expected_status="SAFE",
        description="try / except with guaranteed f.close() in finally:",
    ),
    CorpusTestCase(
        rel_path="python/safe/sqlite_safe.py",
        category="safe",
        resource_type="SQLite connection",
        expected_status="SAFE",
        description="sqlite3.connect() with guaranteed conn.close() in finally:",
    ),
    # 1 Syntax Error
    CorpusTestCase(
        rel_path="python/syntax/invalid_python.py",
        category="syntax",
        resource_type=None,
        expected_status="SYNTAX_ERROR",
        description="Intentional invalid syntax for AST error validation",
    ),
]


def run_benchmark(
    output_json_path: Optional[Path] = None,
    verbose: bool = True,
) -> Dict[str, Any]:
    """Execute the benchmark across all canonical corpus test cases.

    Returns the populated results dictionary.
    """
    engine = AnalysisEngine()
    start_time = time.perf_counter()

    tp = 0  # Expected LEAK, Actual LEAK
    fp = 0  # Expected SAFE or SYNTAX, Actual LEAK
    fn = 0  # Expected LEAK, Actual SAFE
    tn = 0  # Expected SAFE, Actual SAFE
    syntax_tp = 0  # Expected SYNTAX_ERROR, Actual SYNTAX_ERROR
    syntax_fn = 0  # Expected SYNTAX_ERROR, Actual parsed successfully

    case_results: List[Dict[str, Any]] = []

    for test_case in CANONICAL_CORPUS:
        file_path = ROOT_DIR / test_case.rel_path
        if not file_path.exists():
            raise FileNotFoundError(f"Corpus file not found: {file_path}")

        parse_res, issues = engine.analyze_file(file_path)

        # Determine actual status
        if not parse_res.success:
            actual_status = "SYNTAX_ERROR"
        elif len(issues) > 0:
            actual_status = "LEAK"
        else:
            actual_status = "SAFE"

        is_correct = actual_status == test_case.expected_status

        # Update confusion matrix
        if test_case.category == "leak":
            if actual_status == "LEAK":
                tp += 1
            else:
                fn += 1
        elif test_case.category == "safe":
            if actual_status == "SAFE":
                tn += 1
            else:
                fp += 1
        elif test_case.category == "syntax":
            if actual_status == "SYNTAX_ERROR":
                syntax_tp += 1
            else:
                syntax_fn += 1

        # Extract finding details if present
        primary_issue = issues[0] if issues else None
        details = ""
        if primary_issue:
            details = primary_issue.leak_path or primary_issue.problem
        elif actual_status == "SAFE":
            details = "Verified safe on all analyzed paths"
        elif actual_status == "SYNTAX_ERROR":
            details = f"SyntaxError: {parse_res.syntax_error.message}" if parse_res.syntax_error else "SyntaxError"

        case_results.append({
            "file": test_case.rel_path,
            "category": test_case.category,
            "resource_type": test_case.resource_type,
            "description": test_case.description,
            "expected": test_case.expected_status,
            "actual": actual_status,
            "passed": is_correct,
            "issues_count": len(issues),
            "details": details,
            "line": primary_issue.location.line if primary_issue else None,
            "recommendation": primary_issue.recommendation if primary_issue else None,
        })

    elapsed_time = time.perf_counter() - start_time

    # Quality Metrics calculation
    total_valid_code_cases = tp + tn + fp + fn
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1_score = (
        (2 * precision * recall / (precision + recall))
        if (precision + recall) > 0
        else 0.0
    )
    accuracy = (
        ((tp + tn) / total_valid_code_cases)
        if total_valid_code_cases > 0
        else 0.0
    )

    results_data: Dict[str, Any] = {
        "benchmark_metadata": {
            "title": "LeakGuard Python Test Corpus Benchmark",
            "version": "Round 2 Final Jury Version",
            "scope": "Intra-procedural AST Resource Lifecycle Analysis",
            "engine": "Pure Python AST (built-in ast module)",
            "benchmark_scope": "MVP Canonical Test Corpus (12 cases)",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "duration_seconds": round(elapsed_time, 4),
        },
        "summary": {
            "total_cases": len(CANONICAL_CORPUS),
            "expected_leaks": 6,
            "detected_leaks": tp,
            "expected_safe": 5,
            "correct_safe": tn,
            "syntax_cases": 1,
            "correct_syntax": syntax_tp,
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1_score, 4),
            "accuracy": round(accuracy, 4),
        },
        "metrics_definitions": {
            "true_positives": "Expected LEAK correctly identified as LEAK",
            "false_positives": "Expected SAFE incorrectly identified as LEAK",
            "false_negatives": "Expected LEAK incorrectly marked as SAFE",
            "true_negatives": "Expected SAFE correctly verified as SAFE",
            "precision": "TP / (TP + FP) — fraction of reported leaks that are genuine leaks",
            "recall": "TP / (TP + FN) — fraction of all actual leaks that were detected",
            "f1_score": "Harmonic mean of precision and recall",
            "accuracy": "(TP + TN) / Total valid cases",
        },
        "disclaimer": (
            "This benchmark is self-created for the MVP hackathon corpus. "
            "Metrics reflect performance on the 12 included canonical test files. "
            "Cross-function resource ownership is an explicit limitation."
        ),
        "cases": case_results,
    }

    # Save results to JSON file
    if output_json_path is None:
        output_json_path = ROOT_DIR / "benchmark" / "results.json"

    output_json_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_json_path, "w", encoding="utf-8") as f:
        json.dump(results_data, f, indent=2)

    if verbose:
        print_benchmark_report(results_data)

    return results_data


def print_benchmark_report(data: Dict[str, Any]) -> None:
    """Print an actionable, structured benchmark report to console."""
    summary = data["summary"]
    meta = data["benchmark_metadata"]

    print("\n" + "=" * 78)
    print(f"  LeakGuard Automated Benchmark — {meta['version']}")
    print(f"  Scope: {meta['scope']}")
    print("=" * 78)
    print(f" Duration: {meta['duration_seconds']}s | Timestamp: {meta['timestamp']}")
    print("-" * 78)
    print(f"{'Test File':<38} {'Expected':<12} {'Actual':<12} {'Status':<8}")
    print("-" * 78)

    for c in data["cases"]:
        status = "PASS" if c["passed"] else "FAIL"
        print(f"{c['file']:<38} {c['expected']:<12} {c['actual']:<12} {status:<8}")

    print("-" * 78)
    print(" Quality Metrics (Actual Performance on Canonical Corpus):")
    print(f"   * Total Corpus Cases:      {summary['total_cases']}")
    print(f"   * True Positives (TP):     {summary['true_positives']} (detected real leaks)")
    print(f"   * True Negatives (TN):     {summary['true_negatives']} (verified safe code)")
    print(f"   * False Positives (FP):    {summary['false_positives']} (spurious alerts)")
    print(f"   * False Negatives (FN):    {summary['false_negatives']} (missed leaks)")
    print(f"   * Syntax Errors Detected:  {summary['correct_syntax']} / {summary['syntax_cases']}")
    print(f"   * Precision:               {summary['precision'] * 100:.1f}%")
    print(f"   * Recall:                  {summary['recall'] * 100:.1f}%")
    print(f"   * F1 Score:                {summary['f1_score'] * 100:.1f}%")
    print(f"   * Accuracy:                {summary['accuracy'] * 100:.1f}%")
    print("-" * 78)
    print(f" Machine-readable report written to: benchmark/results.json")
    print("=" * 78 + "\n")


if __name__ == "__main__":
    run_benchmark()
