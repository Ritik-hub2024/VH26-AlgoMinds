"""Comprehensive automated tests for resource lifecycle analysis (Round 2 Milestone 1).

Covers:
1. basic file leak still detected
2. explicit close still safe
3. with open still safe
4. early-return leak still detected
5. exception-return leak detected
6. raise leak detected
7. finally cleanup safe
8. exception + finally safe
"""

from pathlib import Path
import pytest

from analyzer.rules.file_leak import FileLeakRule
from parser.ast_parser import ASTParser


@pytest.fixture
def parser() -> ASTParser:
    return ASTParser()


@pytest.fixture
def rule() -> FileLeakRule:
    return FileLeakRule()


@pytest.fixture
def python_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "python"


class TestResourceLifecycleAnalyzer:
    """Test suite covering the 8 Milestone 1 required verification points."""

    # 1. basic file leak still detected
    def test_01_basic_file_leak_detected(self, parser, rule):
        code = """
def load_data():
    f = open("data.txt")
    return f.read()
"""
        parse_res = parser.parse_source(code)
        resources = rule.detect_resources(parse_res.tree)
        assert len(resources) == 1
        assert resources[0].status == "LEAK"
        assert len(rule.issues) == 1
        assert rule.issues[0].resource_name == "f"
        assert "never closed" in rule.issues[0].problem or "return" in rule.issues[0].problem

    # 2. explicit close still safe
    def test_02_explicit_close_still_safe(self, parser, rule):
        code = """
def load_data():
    f = open("data.txt")
    data = f.read()
    f.close()
    return data
"""
        parse_res = parser.parse_source(code)
        resources = rule.detect_resources(parse_res.tree)
        assert len(resources) == 1
        assert resources[0].status == "SAFE"
        assert len(rule.issues) == 0

    # 3. with open still safe
    def test_03_with_open_still_safe(self, parser, rule):
        code = """
def load_data():
    with open("data.txt") as f:
        return f.read()
"""
        parse_res = parser.parse_source(code)
        resources = rule.detect_resources(parse_res.tree)
        assert len(resources) == 1
        assert resources[0].status == "SAFE"
        assert resources[0].is_context_manager is True
        assert len(rule.issues) == 0

    # 4. early-return leak still detected
    def test_04_early_return_leak_detected(self, parser, rule):
        code = """
def parse_header_or_skip(filename, skip):
    f = open(filename, "r")
    if skip:
        return "SKIPPED"
    header = f.readline()
    f.close()
    return header
"""
        parse_res = parser.parse_source(code)
        resources = rule.detect_resources(parse_res.tree)
        assert len(resources) == 1
        assert resources[0].status == "LEAK"
        assert len(rule.issues) == 1
        assert "if skip" in rule.issues[0].leak_path
        assert "return (leak)" in rule.issues[0].leak_path

    # 5. exception-return leak detected
    def test_05_exception_return_leak_detected(self, parser, rule):
        code = """
def load_data():
    f = open("data.txt")
    try:
        risky_operation()
    except Exception:
        return None
    f.close()
"""
        parse_res = parser.parse_source(code)
        resources = rule.detect_resources(parse_res.tree)
        assert len(resources) == 1
        assert resources[0].status == "LEAK"
        assert len(rule.issues) == 1
        issue = rule.issues[0]
        assert "except Exception" in issue.leak_path
        assert "return (leak)" in issue.leak_path
        assert "not closed on exception path" in issue.problem

    # 6. raise leak detected
    def test_06_raise_leak_detected(self, parser, rule):
        code = """
def load_data():
    f = open("data.txt")
    raise RuntimeError("failure")
    f.close()
"""
        parse_res = parser.parse_source(code)
        resources = rule.detect_resources(parse_res.tree)
        assert len(resources) == 1
        assert resources[0].status == "LEAK"
        assert len(rule.issues) == 1
        assert "raise (leak)" in rule.issues[0].leak_path

    # 7. finally cleanup safe
    def test_07_finally_cleanup_safe(self, parser, rule):
        code = """
def load_data():
    f = open("data.txt")
    try:
        return f.read()
    finally:
        f.close()
"""
        parse_res = parser.parse_source(code)
        resources = rule.detect_resources(parse_res.tree)
        assert len(resources) == 1
        assert resources[0].status == "SAFE"
        assert len(rule.issues) == 0

    # 8. exception + finally safe
    def test_08_exception_plus_finally_safe(self, parser, rule):
        code = """
def load_data():
    f = open("data.txt")
    try:
        risky_operation()
    except Exception:
        handle_error()
    finally:
        f.close()
"""
        parse_res = parser.parse_source(code)
        resources = rule.detect_resources(parse_res.tree)
        assert len(resources) == 1
        assert resources[0].status == "SAFE"
        assert len(rule.issues) == 0

    # 9. nested / combined case: nested try-finally safe
    def test_09_nested_try_finally_safe(self, parser, rule):
        code = """
def load_data():
    f = open("data.txt")
    try:
        try:
            risky_operation()
        finally:
            f.close()
    except Exception:
        handle_error()
"""
        parse_res = parser.parse_source(code)
        resources = rule.detect_resources(parse_res.tree)
        assert len(resources) == 1
        assert resources[0].status == "SAFE"
        assert len(rule.issues) == 0

    # 10. nested / combined case: nested try exception return leak
    def test_10_nested_exception_return_leak(self, parser, rule):
        code = """
def load_data():
    f = open("data.txt")
    try:
        try:
            risky_operation()
        except ValueError:
            return None
    except Exception:
        pass
    f.close()
"""
        parse_res = parser.parse_source(code)
        resources = rule.detect_resources(parse_res.tree)
        assert len(resources) == 1
        assert resources[0].status == "LEAK"
        assert len(rule.issues) == 1
        assert "return (leak)" in rule.issues[0].leak_path

    # 11. nested / combined case: branching inside try with finally cleanup safe
    def test_11_combined_branching_in_try_finally_safe(self, parser, rule):
        code = """
def load_data(flag):
    f = open("data.txt")
    try:
        if flag:
            return "early"
        return f.read()
    finally:
        f.close()
"""
        parse_res = parser.parse_source(code)
        resources = rule.detect_resources(parse_res.tree)
        assert len(resources) == 1
        assert resources[0].status == "SAFE"
        assert len(rule.issues) == 0

    # 12. Exact snippets verification for Cases A, B, C, D, E from milestone prompt
    def test_12_exact_milestone_cases_a_through_e(self, parser):
        # CASE A — MUST REPORT LEAK
        case_a = """
def load():
    f = open("data.txt")

    try:
        risky_operation()
    except Exception:
        return None

    f.close()
"""
        rule_a = FileLeakRule()
        res_a = rule_a.detect_resources(parser.parse_source(case_a).tree)
        assert len(res_a) == 1
        assert res_a[0].status == "LEAK"
        assert len(rule_a.issues) == 1
        assert "except Exception" in rule_a.issues[0].leak_path
        assert "return (leak)" in rule_a.issues[0].leak_path
        assert "not closed on exception path" in rule_a.issues[0].problem

        # CASE B — MUST REPORT LEAK
        case_b = """
def load():
    f = open("data.txt")
    raise RuntimeError("failed")
    f.close()
"""
        rule_b = FileLeakRule()
        res_b = rule_b.detect_resources(parser.parse_source(case_b).tree)
        assert len(res_b) == 1
        assert res_b[0].status == "LEAK"
        assert len(rule_b.issues) == 1
        assert "raise (leak)" in rule_b.issues[0].leak_path

        # CASE C — MUST REPORT SAFE
        case_c = """
def load():
    f = open("data.txt")

    try:
        return f.read()
    finally:
        f.close()
"""
        rule_c = FileLeakRule()
        res_c = rule_c.detect_resources(parser.parse_source(case_c).tree)
        assert len(res_c) == 1
        assert res_c[0].status == "SAFE"
        assert len(rule_c.issues) == 0

        # CASE D — MUST REPORT SAFE
        case_d = """
def load():
    f = open("data.txt")

    try:
        risky_operation()
    except Exception:
        handle_error()
    finally:
        f.close()
"""
        rule_d = FileLeakRule()
        res_d = rule_d.detect_resources(parser.parse_source(case_d).tree)
        assert len(res_d) == 1
        assert res_d[0].status == "SAFE"
        assert len(rule_d.issues) == 0

        # CASE E — MUST CONTINUE PASSING
        case_e = """
with open("data.txt") as f:
    return f.read()
"""
        rule_e = FileLeakRule()
        res_e = rule_e.detect_resources(parser.parse_source(case_e).tree)
        assert len(res_e) == 1
        assert res_e[0].status == "SAFE"
        assert res_e[0].is_context_manager is True
        assert len(rule_e.issues) == 0

    # 13. Verify structured finding dimensions
    def test_13_finding_data_structure_dimensions(self, parser, rule):
        code = """
def load():
    f = open("data.txt")
    try:
        risky_operation()
    except Exception:
        return None
    f.close()
"""
        parse_res = parser.parse_source(code)
        resources = rule.detect_resources(parse_res.tree)
        assert len(rule.issues) == 1
        issue = rule.issues[0]

        d = issue.to_dict()
        # Required dimensions: resource, variable, opened line, path, reason, cleanup status, severity
        assert d["resource"] == "f (file)"
        assert d["variable"] == "f"
        assert d["opened_line"] == 3
        assert "open()" in d["path"] and "return (leak)" in d["path"]
        assert "not closed on exception path" in d["reason"]
        assert d["cleanup_status"] == "UNCLOSED"
        assert d["severity"] == "HIGH"


class TestNewPythonSampleFiles:
    """Test the newly added sample files under python/leaks and python/safe."""

    def test_sample_exception_leak_py(self, parser, rule, python_dir):
        file_path = python_dir / "leaks" / "exception_leak.py"
        assert file_path.exists()
        parse_res = parser.parse_file(file_path)
        assert parse_res.success
        resources = rule.detect_resources(parse_res.tree, file_path=str(file_path))
        assert len(resources) == 1
        assert resources[0].status == "LEAK"
        assert len(rule.issues) == 1
        assert "except Exception" in rule.issues[0].leak_path
        assert "return (leak)" in rule.issues[0].leak_path

    def test_sample_raise_leak_py(self, parser, rule, python_dir):
        file_path = python_dir / "leaks" / "raise_leak.py"
        assert file_path.exists()
        parse_res = parser.parse_file(file_path)
        assert parse_res.success
        resources = rule.detect_resources(parse_res.tree, file_path=str(file_path))
        assert len(resources) == 1
        assert resources[0].status == "LEAK"
        assert len(rule.issues) == 1
        assert "raise (leak)" in rule.issues[0].leak_path

    def test_sample_finally_close_py(self, parser, rule, python_dir):
        file_path = python_dir / "safe" / "finally_close.py"
        assert file_path.exists()
        parse_res = parser.parse_file(file_path)
        assert parse_res.success
        resources = rule.detect_resources(parse_res.tree, file_path=str(file_path))
        assert len(resources) == 1
        assert resources[0].status == "SAFE"
        assert len(rule.issues) == 0

    def test_sample_exception_finally_py(self, parser, rule, python_dir):
        file_path = python_dir / "safe" / "exception_finally.py"
        assert file_path.exists()
        parse_res = parser.parse_file(file_path)
        assert parse_res.success
        resources = rule.detect_resources(parse_res.tree, file_path=str(file_path))
        assert len(resources) == 1
        assert resources[0].status == "SAFE"
        assert len(rule.issues) == 0

    def test_sample_sqlite_leak_py(self, parser, python_dir):
        from analyzer.rules.sqlite_leak import SqliteLeakRule
        sqlite_rule = SqliteLeakRule()
        file_path = python_dir / "leaks" / "sqlite_leak.py"
        assert file_path.exists()
        parse_res = parser.parse_file(file_path)
        assert parse_res.success
        resources = sqlite_rule.detect_resources(parse_res.tree, file_path=str(file_path))
        assert len(resources) == 1
        assert resources[0].status == "LEAK"
        assert resources[0].resource_type == "SQLite connection"
        assert resources[0].opening_line == 5

    def test_sample_sqlite_early_return_py(self, parser, python_dir):
        from analyzer.rules.sqlite_leak import SqliteLeakRule
        sqlite_rule = SqliteLeakRule()
        file_path = python_dir / "leaks" / "sqlite_early_return.py"
        assert file_path.exists()
        parse_res = parser.parse_file(file_path)
        assert parse_res.success
        resources = sqlite_rule.detect_resources(parse_res.tree, file_path=str(file_path))
        assert len(resources) == 1
        assert resources[0].status == "LEAK"
        assert resources[0].resource_type == "SQLite connection"
        assert resources[0].opening_line == 5

    def test_sample_sqlite_safe_py(self, parser, python_dir):
        from analyzer.rules.sqlite_leak import SqliteLeakRule
        sqlite_rule = SqliteLeakRule()
        file_path = python_dir / "safe" / "sqlite_safe.py"
        assert file_path.exists()
        parse_res = parser.parse_file(file_path)
        assert parse_res.success
        resources = sqlite_rule.detect_resources(parse_res.tree, file_path=str(file_path))
        assert len(resources) == 1
        assert resources[0].status == "SAFE"
        assert resources[0].resource_type == "SQLite connection"
        assert resources[0].closing_line == 11

    def test_sample_invalid_syntax_py(self, parser, python_dir):
        file_path = python_dir / "syntax" / "invalid_python.py"
        assert file_path.exists()
        parse_res = parser.parse_file(file_path)
        assert not parse_res.success
        assert parse_res.tree is None
        assert parse_res.syntax_error is not None
        assert "invalid syntax" in parse_res.syntax_error.message.lower() or parse_res.syntax_error.line is not None


class TestCanonicalCorpusSuite:
    """Validate all 12 canonical Python test corpus files using AnalysisEngine."""

    @pytest.fixture
    def engine(self):
        from analyzer.engine import AnalysisEngine
        return AnalysisEngine()

    # Intentional Leaks (6 cases)
    def test_corpus_leak_file_no_close(self, engine, python_dir):
        res, issues = engine.analyze_file(python_dir / "leaks" / "file_no_close.py")
        assert res.success
        assert len(issues) == 1
        assert issues[0].resource_type == "file"
        assert issues[0].location.line == 4
        assert issues[0].rule_id == "LEAK001"

    def test_corpus_leak_early_return(self, engine, python_dir):
        res, issues = engine.analyze_file(python_dir / "leaks" / "early_return.py")
        assert res.success
        assert len(issues) == 1
        assert issues[0].resource_type == "file"
        assert issues[0].location.line == 4
        assert "return" in issues[0].leak_path

    def test_corpus_leak_exception_path(self, engine, python_dir):
        res, issues = engine.analyze_file(python_dir / "leaks" / "exception_leak.py")
        assert res.success
        assert len(issues) == 1
        assert issues[0].resource_type == "file"
        assert issues[0].location.line == 5
        assert "except" in issues[0].leak_path

    def test_corpus_leak_raise(self, engine, python_dir):
        res, issues = engine.analyze_file(python_dir / "leaks" / "raise_leak.py")
        assert res.success
        assert len(issues) == 1
        assert issues[0].resource_type == "file"
        assert issues[0].location.line == 5
        assert "raise" in issues[0].leak_path

    def test_corpus_leak_sqlite(self, engine, python_dir):
        res, issues = engine.analyze_file(python_dir / "leaks" / "sqlite_leak.py")
        assert res.success
        assert len(issues) == 1
        assert issues[0].resource_type == "SQLite connection"
        assert issues[0].location.line == 5
        assert issues[0].rule_id == "LEAK002"

    def test_corpus_leak_sqlite_early_return(self, engine, python_dir):
        res, issues = engine.analyze_file(python_dir / "leaks" / "sqlite_early_return.py")
        assert res.success
        assert len(issues) == 1
        assert issues[0].resource_type == "SQLite connection"
        assert issues[0].location.line == 5
        assert "return" in issues[0].leak_path

    # Safe Patterns (5 cases)
    def test_corpus_safe_explicit_close(self, engine, python_dir):
        res, issues = engine.analyze_file(python_dir / "safe" / "explicit_close.py")
        assert res.success
        assert len(issues) == 0

    def test_corpus_safe_with_file(self, engine, python_dir):
        res, issues = engine.analyze_file(python_dir / "safe" / "with_file.py")
        assert res.success
        assert len(issues) == 0

    def test_corpus_safe_finally_close(self, engine, python_dir):
        res, issues = engine.analyze_file(python_dir / "safe" / "finally_close.py")
        assert res.success
        assert len(issues) == 0

    def test_corpus_safe_exception_finally(self, engine, python_dir):
        res, issues = engine.analyze_file(python_dir / "safe" / "exception_finally.py")
        assert res.success
        assert len(issues) == 0

    def test_corpus_safe_sqlite(self, engine, python_dir):
        res, issues = engine.analyze_file(python_dir / "safe" / "sqlite_safe.py")
        assert res.success
        assert len(issues) == 0

    # Syntax Error (1 case)
    def test_corpus_syntax_error(self, engine, python_dir):
        res, issues = engine.analyze_file(python_dir / "syntax" / "invalid_python.py")
        assert not res.success
        assert res.syntax_error is not None
        assert len(issues) == 0


