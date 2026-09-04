"""Automated regression test suite for Step 9: Benchmark Expansion + Accuracy Hardening.

Verifies:
1. Benchmark cases have valid and non-empty configurations.
2. Canonical benchmark corpus contains no duplicate relative paths.
3. Every LEAK case yields actual status LEAK.
4. Every SAFE case yields actual status SAFE.
5. Every UNKNOWN case yields actual status UNKNOWN.
6. Every SYNTAX case yields actual status SYNTAX_ERROR.
7. Metrics formulas (Precision, Recall, F1, Accuracy, Unknown Rate) are mathematically consistent.
8. UNKNOWN cases are strictly isolated and never conflated into TP, TN, FP, or FN.
9. Benchmark execution is deterministic and reproducible.
10. Previous Step-8 benchmark cases remain intact with preserved expectations.
11. Focused regression: loop early exit skipping cleanup is detected as LEAK.
"""

from pathlib import Path
import pytest

from analyzer.engine import AnalysisEngine
from benchmark.run_benchmark import CANONICAL_CORPUS, run_benchmark

ROOT_DIR = Path(__file__).resolve().parent.parent


class TestBenchmarkSuite:
    """Test suite covering the expanded 46-case canonical benchmark."""

    def test_benchmark_cases_count_and_categories(self):
        """Verify the corpus contains at least 40 cases with the recommended category distribution."""
        assert len(CANONICAL_CORPUS) >= 40
        assert len(CANONICAL_CORPUS) == 46

        leaks = [c for c in CANONICAL_CORPUS if c.category == "leak"]
        safes = [c for c in CANONICAL_CORPUS if c.category == "safe"]
        unknowns = [c for c in CANONICAL_CORPUS if c.category == "unknown"]
        syntax = [c for c in CANONICAL_CORPUS if c.category == "syntax"]

        assert len(leaks) == 16
        assert len(safes) == 16
        assert len(unknowns) == 10
        assert len(syntax) == 4

    def test_benchmark_no_duplicate_paths(self):
        """Verify that all relative paths in the corpus are unique."""
        paths = [c.rel_path for c in CANONICAL_CORPUS]
        assert len(paths) == len(set(paths)), "Duplicate test corpus paths detected!"

    def test_all_corpus_files_exist(self):
        """Verify that every registered corpus file physically exists on disk."""
        for case in CANONICAL_CORPUS:
            file_path = ROOT_DIR / case.rel_path
            assert file_path.exists(), f"Corpus file missing: {case.rel_path}"

    def test_leak_cases_produce_leak(self):
        """Verify that every LEAK case is detected as a genuine LEAK."""
        engine = AnalysisEngine()
        leak_cases = [c for c in CANONICAL_CORPUS if c.category == "leak"]
        for case in leak_cases:
            file_path = ROOT_DIR / case.rel_path
            parse_res, issues = engine.analyze_file(file_path)
            assert parse_res.success, f"Unexpected syntax failure in leak file: {case.rel_path}"
            assert any(getattr(i, "classification", "LEAK") == "LEAK" for i in issues), (
                f"Expected LEAK but none detected in {case.rel_path}"
            )

    def test_safe_cases_produce_safe(self):
        """Verify that every SAFE case produces zero leaks and is classified SAFE."""
        engine = AnalysisEngine()
        safe_cases = [c for c in CANONICAL_CORPUS if c.category == "safe"]
        for case in safe_cases:
            file_path = ROOT_DIR / case.rel_path
            parse_res, issues = engine.analyze_file(file_path)
            assert parse_res.success, f"Unexpected syntax failure in safe file: {case.rel_path}"
            assert len(issues) == 0, f"Expected SAFE but findings detected in {case.rel_path}: {issues}"

    def test_unknown_cases_produce_unknown(self):
        """Verify that every UNKNOWN case is classified as UNKNOWN."""
        engine = AnalysisEngine()
        unknown_cases = [c for c in CANONICAL_CORPUS if c.category == "unknown"]
        for case in unknown_cases:
            file_path = ROOT_DIR / case.rel_path
            parse_res, issues = engine.analyze_file(file_path)
            assert parse_res.success, f"Unexpected syntax failure in unknown file: {case.rel_path}"
            assert any(getattr(i, "classification", "LEAK") == "UNKNOWN" for i in issues), (
                f"Expected UNKNOWN classification in {case.rel_path}"
            )
            # Ensure no false LEAK classification is present
            assert not any(getattr(i, "classification", "LEAK") == "LEAK" for i in issues), (
                f"Ambiguous case {case.rel_path} was incorrectly marked as definite LEAK"
            )

    def test_syntax_cases_produce_syntax_error(self):
        """Verify that malformed Python samples produce SYNTAX_ERROR."""
        engine = AnalysisEngine()
        syntax_cases = [c for c in CANONICAL_CORPUS if c.category == "syntax"]
        for case in syntax_cases:
            file_path = ROOT_DIR / case.rel_path
            parse_res, issues = engine.analyze_file(file_path)
            assert not parse_res.success, f"Expected syntax error in {case.rel_path} but parsed successfully"
            assert parse_res.syntax_error is not None

    def test_metrics_calculation_consistency(self, tmp_path):
        """Verify mathematical integrity of benchmark quality metrics."""
        results = run_benchmark(output_json_path=tmp_path / "bench_test.json", verbose=False)
        summary = results["summary"]

        tp = summary["true_positives"]
        tn = summary["true_negatives"]
        fp = summary["false_positives"]
        fn = summary["false_negatives"]
        unknown = summary["unknown_positives"]
        syntax = summary["correct_syntax"]

        # Assert no cross-contamination
        assert fp == 0
        assert fn == 0
        assert tp == 16
        assert tn == 16
        assert unknown == 10
        assert syntax == 4

        expected_precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        expected_recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        expected_f1 = (
            2 * expected_precision * expected_recall / (expected_precision + expected_recall)
            if (expected_precision + expected_recall) > 0
            else 0.0
        )
        expected_accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0
        expected_unknown_rate = unknown / summary["total_cases"]

        assert summary["precision"] == round(expected_precision, 4)
        assert summary["recall"] == round(expected_recall, 4)
        assert summary["f1_score"] == round(expected_f1, 4)
        assert summary["accuracy"] == round(expected_accuracy, 4)
        assert summary["unknown_rate"] == round(expected_unknown_rate, 4)

    def test_unknown_excluded_from_confusion_matrix(self, tmp_path):
        """Verify that UNKNOWN is never added to TP, TN, FP, or FN."""
        results = run_benchmark(output_json_path=tmp_path / "bench_test.json", verbose=False)
        summary = results["summary"]

        definite_sum = (
            summary["true_positives"]
            + summary["true_negatives"]
            + summary["false_positives"]
            + summary["false_negatives"]
        )
        assert definite_sum == 32  # 16 leak + 16 safe
        # Total cases must equal definite_sum + unknown + syntax
        assert summary["total_cases"] == definite_sum + summary["unknown_positives"] + summary["correct_syntax"]

    def test_benchmark_determinism(self, tmp_path):
        """Verify that repeated benchmark runs produce deterministic results."""
        res1 = run_benchmark(output_json_path=tmp_path / "bench_1.json", verbose=False)
        res2 = run_benchmark(output_json_path=tmp_path / "bench_2.json", verbose=False)

        assert res1["summary"] == res2["summary"]
        assert [c["actual"] for c in res1["cases"]] == [c["actual"] for c in res2["cases"]]

    def test_step8_cases_preserved(self):
        """Verify that the original 21 Step-8 benchmark cases remain identical in behavior."""
        step8_files = {
            "python/leaks/file_no_close.py": "LEAK",
            "python/leaks/early_return.py": "LEAK",
            "python/leaks/exception_leak.py": "LEAK",
            "python/leaks/raise_leak.py": "LEAK",
            "python/leaks/sqlite_leak.py": "LEAK",
            "python/leaks/sqlite_early_return.py": "LEAK",
            "python/leaks/reassignment_leak.py": "LEAK",
            "python/leaks/alias_leak.py": "LEAK",
            "python/safe/explicit_close.py": "SAFE",
            "python/safe/with_file.py": "SAFE",
            "python/safe/finally_close.py": "SAFE",
            "python/safe/exception_finally.py": "SAFE",
            "python/safe/sqlite_safe.py": "SAFE",
            "python/safe/reassignment_safe.py": "SAFE",
            "python/safe/alias_safe.py": "SAFE",
            "python/safe/callee_closes_resource.py": "SAFE",
            "python/unknown/transfer_unknown.py": "UNKNOWN",
            "python/unknown/return_unknown.py": "UNKNOWN",
            "python/unknown/attribute_unknown.py": "UNKNOWN",
            "python/unknown/collection_unknown.py": "UNKNOWN",
            "python/syntax/invalid_python.py": "SYNTAX_ERROR",
        }

        corpus_dict = {c.rel_path: c.expected_status for c in CANONICAL_CORPUS}
        for rel_path, expected in step8_files.items():
            assert rel_path in corpus_dict, f"Step 8 case missing: {rel_path}"
            assert corpus_dict[rel_path] == expected, f"Step 8 expectation changed for {rel_path}"

    def test_loop_early_exit_leak_detection(self):
        """Focused regression test: verify early exits inside loops skipping close are detected."""
        engine = AnalysisEngine()
        res, issues = engine.analyze_file(ROOT_DIR / "python/leaks/leak_loop_skip.py")
        assert res.success
        assert len(issues) == 1
        issue = issues[0]
        assert issue.classification == "LEAK"
        assert "loop" in issue.leak_path
        assert issue.location.line == 5  # line where open() occurs
