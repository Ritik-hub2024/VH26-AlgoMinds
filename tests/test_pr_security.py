"""Tests for GitHub PR Security Experience (Baseline, Differential Gating, Policy, SARIF)."""

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

from cli import main, scan_target
from models.issue import LeakIssue, Severity
from models.location import SourceLocation
from models.policy import BlockLevel, SecurityPolicy
from models.baseline import (
    compute_finding_fingerprint,
    load_baseline,
    normalize_path,
    DifferentialReport,
)
from reporter.markdown import MarkdownReporter
from reporter.sarif import SARIFReporter


class TestPRSecurityExperience(unittest.TestCase):
    """Test deterministic baselines, security policies, differential gating, and SARIF export."""

    def setUp(self):
        self.root_dir = Path(__file__).resolve().parent.parent
        self.python_safe = self.root_dir / "python" / "safe"
        self.python_leaks = self.root_dir / "python" / "leaks"
        self.examples_dir = self.root_dir / "examples"

    def test_backwards_compatibility_no_baseline(self):
        """Without baseline, safe targets exit 0 and targets with leaks exit 1."""
        code_safe = main(["--target", str(self.python_safe)])
        self.assertEqual(code_safe, 0)

        code_leak = main(["--target", str(self.python_leaks)])
        self.assertEqual(code_leak, 1)

    def test_stable_fingerprint_computation(self):
        """Fingerprints must be deterministic across path styles and platforms."""
        issue1 = LeakIssue(
            rule_id="LEAK001",
            message="Unclosed file descriptor",
            severity=Severity.HIGH,
            location=SourceLocation(file_path="foo/bar/test.py", line=42, column=5),
            resource_name="f",
            resource_type="file",
        )
        fp1 = compute_finding_fingerprint(issue1)
        self.assertEqual(fp1, "LEAK001:foo/bar/test.py:42:file:f")

        # Windows-style backslashes must normalize to forward slashes
        issue_win = LeakIssue(
            rule_id="LEAK001",
            message="Unclosed file descriptor",
            severity=Severity.HIGH,
            location=SourceLocation(file_path="foo\\bar\\test.py", line=42, column=5),
            resource_name="f",
            resource_type="file",
        )
        fp_win = compute_finding_fingerprint(issue_win)
        self.assertEqual(fp_win, "LEAK001:foo/bar/test.py:42:file:f")

    def test_baseline_generation_and_tolerated_existing_leaks(self):
        """A PR with pre-existing baseline leaks only must PASS with exit code 0."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            baseline_file = Path(tmp_dir) / "baseline.json"

            # 1. Export baseline from python/leaks
            gen_code = main([
                "--target", str(self.python_leaks),
                "--baseline-out", str(baseline_file),
                "--no-color",
            ])
            self.assertEqual(gen_code, 1)  # Initial run had leaks without baseline
            self.assertTrue(baseline_file.exists())

            # Verify baseline contents
            baseline_data = json.loads(baseline_file.read_text(encoding="utf-8"))
            self.assertIn("fingerprints", baseline_data)
            self.assertGreater(len(baseline_data["fingerprints"]), 0)

            # 2. Re-scan the same target WITH the baseline -> must PASS (exit 0)
            summary_file = Path(tmp_dir) / "summary.md"
            pr_code = main([
                "--target", str(self.python_leaks),
                "--baseline", str(baseline_file),
                "--github-summary", str(summary_file),
                "--no-color",
            ])
            self.assertEqual(pr_code, 0, "Scan with matching baseline must exit 0")

            # Check GitHub summary output
            self.assertTrue(summary_file.exists())
            summary_content = summary_file.read_text(encoding="utf-8")
            self.assertIn("PR PASSED", summary_content)
            self.assertIn("EXISTING / BASELINE FINDINGS", summary_content)
            self.assertIn("TOLERATED", summary_content)

    def test_pr_with_new_blocking_leak_fails(self):
        """A PR introducing a NEW leak not in baseline must block with exit code 1."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            project_dir = Path(tmp_dir) / "repo"
            project_dir.mkdir()

            file1 = project_dir / "existing_leak.py"
            file1.write_text(
                "def old_func():\n"
                "    f = open('old.txt')\n"
                "    return 1\n",
                encoding="utf-8",
            )

            baseline_file = Path(tmp_dir) / "baseline.json"
            main(["--target", str(project_dir), "--baseline-out", str(baseline_file)])
            self.assertTrue(baseline_file.exists())

            # Now developer adds a second leaking file
            file2 = project_dir / "new_leak.py"
            file2.write_text(
                "def new_func():\n"
                "    f2 = open('new.txt')\n"
                "    return 2\n",
                encoding="utf-8",
            )

            summary_file = Path(tmp_dir) / "summary.md"
            pr_code = main([
                "--target", str(project_dir),
                "--baseline", str(baseline_file),
                "--github-summary", str(summary_file),
            ])
            self.assertEqual(pr_code, 1, "PR with new leak must exit 1 (blocked)")

            summary_content = summary_file.read_text(encoding="utf-8")
            self.assertIn("PR BLOCKED", summary_content)
            self.assertIn("NEW FINDINGS", summary_content)
            self.assertIn("BLOCKING", summary_content)
            self.assertIn("new_leak.py", summary_content)
            self.assertIn("EXISTING / BASELINE FINDINGS", summary_content)
            self.assertIn("existing_leak.py", summary_content)

    def test_pr_with_multiple_new_leaks_blocks(self):
        """A PR introducing multiple new leaks reports all new leaks and blocks."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            project_dir = Path(tmp_dir) / "repo"
            project_dir.mkdir()

            base_file = project_dir / "base.py"
            base_file.write_text("x = 1\n", encoding="utf-8")

            baseline_file = Path(tmp_dir) / "baseline.json"
            main(["--target", str(project_dir), "--baseline-out", str(baseline_file)])

            # Introduce two new leaks
            leak1 = project_dir / "leak1.py"
            leak1.write_text("def f1():\n    f = open('a.txt')\n    return 1\n", encoding="utf-8")

            leak2 = project_dir / "leak2.py"
            leak2.write_text("def f2():\n    f = open('b.txt')\n    return 2\n", encoding="utf-8")

            pr_code = main([
                "--target", str(project_dir),
                "--baseline", str(baseline_file),
            ])
            self.assertEqual(pr_code, 1)

    def test_syntax_error_always_blocks_even_with_baseline(self):
        """Syntax errors must always fail the gate (exit 1), regardless of baseline."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            baseline_file = Path(tmp_dir) / "empty_baseline.json"
            baseline_file.write_text(json.dumps({"fingerprints": []}), encoding="utf-8")

            invalid_target = self.examples_dir / "invalid_syntax_sample.py"
            summary_file = Path(tmp_dir) / "summary.md"
            code = main([
                "--target", str(invalid_target),
                "--baseline", str(baseline_file),
                "--github-summary", str(summary_file),
            ])
            self.assertEqual(code, 1, "Syntax error must block gate")

            summary_content = summary_file.read_text(encoding="utf-8")
            self.assertIn("SYNTAX ERRORS", summary_content)
            self.assertIn("PR BLOCKED", summary_content)

    def test_security_policy_thresholds(self):
        """Policy configuration allows warning on lower severities while blocking on higher."""
        policy_high = SecurityPolicy(BlockLevel.HIGH)
        self.assertTrue(policy_high.is_blocking(Severity.CRITICAL))
        self.assertTrue(policy_high.is_blocking(Severity.HIGH))
        self.assertFalse(policy_high.is_blocking(Severity.MEDIUM))
        self.assertTrue(policy_high.is_warning(Severity.MEDIUM))
        self.assertFalse(policy_high.is_blocking(Severity.LOW))

        policy_med = SecurityPolicy(BlockLevel.MEDIUM)
        self.assertTrue(policy_med.is_blocking(Severity.MEDIUM))
        self.assertTrue(policy_med.is_blocking(Severity.HIGH))
        self.assertFalse(policy_med.is_blocking(Severity.LOW))

        policy_low = SecurityPolicy(BlockLevel.LOW)
        self.assertTrue(policy_low.is_blocking(Severity.LOW))
        self.assertTrue(policy_low.is_blocking(Severity.MEDIUM))

    def test_sarif_v2_1_0_validity(self):
        """SARIF output must be valid OASIS SARIF v2.1.0 format with proper metadata."""
        report = scan_target(str(self.python_leaks))
        sarif_reporter = SARIFReporter()
        sarif_data = sarif_reporter.to_sarif_dict(report)

        self.assertEqual(sarif_data["version"], "2.1.0")
        self.assertIn("sarif-schema-2.1.0.json", sarif_data["$schema"])
        self.assertEqual(len(sarif_data["runs"]), 1)

        run = sarif_data["runs"][0]
        driver = run["tool"]["driver"]
        self.assertEqual(driver["name"], "LeakGuard")
        rule_ids = {r["id"] for r in driver["rules"]}
        self.assertIn("LEAK001", rule_ids)
        self.assertIn("LEAK002", rule_ids)

        # Check results
        results = run["results"]
        self.assertGreater(len(results), 0)
        first = results[0]
        self.assertIn(first["ruleId"], rule_ids)
        self.assertIn("level", first)
        self.assertIn("locations", first)
        loc = first["locations"][0]["physicalLocation"]
        self.assertIn("artifactLocation", loc)
        self.assertIn("region", loc)
        self.assertGreater(loc["region"]["startLine"], 0)

    def test_cli_sarif_format_stdout(self):
        """CLI -f sarif writes valid SARIF JSON to stdout."""
        captured = io.StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = captured
            main(["--target", str(self.python_safe), "-f", "sarif"])
        finally:
            sys.stdout = old_stdout

        out = captured.getvalue()
        sarif_json = json.loads(out)
        self.assertEqual(sarif_json["version"], "2.1.0")
        self.assertEqual(len(sarif_json["runs"][0]["results"]), 0)

    def test_cli_sarif_format_output_file(self):
        """CLI -f sarif -o results.sarif writes valid SARIF file."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_file = Path(tmp_dir) / "results.sarif"
            main(["--target", str(self.python_leaks), "-f", "sarif", "-o", str(out_file)])
            self.assertTrue(out_file.exists())
            data = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertEqual(data["version"], "2.1.0")
            self.assertGreater(len(data["runs"][0]["results"]), 0)

    def test_cli_sarif_with_baseline_gating_creates_valid_sarif(self):
        """CLI SARIF generation with baseline returns exit 0 and genuinely creates results.sarif."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            bl_file = Path(tmp_dir) / "leak_baseline.json"
            out_file = Path(tmp_dir) / "results.sarif"

            # 1. Generate baseline
            code_bl = main(["--target", str(self.python_leaks), "--baseline-out", str(bl_file)])
            self.assertEqual(code_bl, 1)
            self.assertTrue(bl_file.exists())

            # 2. Run SARIF generation with baseline (must exit 0)
            code_sarif = main([
                "--target", str(self.python_leaks),
                "--baseline", str(bl_file),
                "-f", "sarif",
                "-o", str(out_file),
            ])
            self.assertEqual(code_sarif, 0)
            self.assertTrue(out_file.exists())

            # 3. Validate SARIF JSON content
            data = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertEqual(data["version"], "2.1.0")
            self.assertEqual(data["runs"][0]["tool"]["driver"]["name"], "LeakGuard")
            results = data["runs"][0]["results"]
            self.assertGreaterEqual(len(results), 1)
            for res in results:
                self.assertIn("ruleId", res)
                self.assertIn("level", res)
                self.assertIn("locations", res)
                loc = res["locations"][0]["physicalLocation"]
                self.assertGreater(loc["region"]["startLine"], 0)
                self.assertTrue(not loc["artifactLocation"]["uri"].startswith("/"))

    def test_cli_sarif_nested_dir_and_auto_format(self):
        """CLI automatically creates parent directories and detects SARIF format from .sarif extension."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            nested_sarif = Path(tmp_dir) / "nested" / "deep" / "results.sarif"
            self.assertFalse(nested_sarif.parent.exists())

            # Call without -f sarif; extension should auto-detect sarif
            code = main(["--target", str(self.python_safe), "-o", str(nested_sarif)])
            self.assertEqual(code, 0)
            self.assertTrue(nested_sarif.exists())
            data = json.loads(nested_sarif.read_text(encoding="utf-8"))
            self.assertEqual(data["version"], "2.1.0")
            self.assertEqual(data["runs"][0]["tool"]["driver"]["name"], "LeakGuard")


if __name__ == "__main__":
    unittest.main()
