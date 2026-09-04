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

    def test_sample_database_leak_py(self, parser, python_dir):
        from analyzer.rules.sqlite_leak import SqliteLeakRule
        sqlite_rule = SqliteLeakRule()
        file_path = python_dir / "leaks" / "database_leak.py"
        assert file_path.exists()
        parse_res = parser.parse_file(file_path)
        assert parse_res.success
        resources = sqlite_rule.detect_resources(parse_res.tree, file_path=str(file_path))
        assert len(resources) == 1
        assert resources[0].status == "LEAK"
        assert resources[0].resource_type == "SQLite connection"

    def test_sample_database_early_return_py(self, parser, python_dir):
        from analyzer.rules.sqlite_leak import SqliteLeakRule
        sqlite_rule = SqliteLeakRule()
        file_path = python_dir / "leaks" / "database_early_return.py"
        assert file_path.exists()
        parse_res = parser.parse_file(file_path)
        assert parse_res.success
        resources = sqlite_rule.detect_resources(parse_res.tree, file_path=str(file_path))
        assert len(resources) == 1
        assert resources[0].status == "LEAK"
        assert resources[0].resource_type == "SQLite connection"

    def test_sample_database_safe_py(self, parser, python_dir):
        from analyzer.rules.sqlite_leak import SqliteLeakRule
        sqlite_rule = SqliteLeakRule()
        file_path = python_dir / "safe" / "database_safe.py"
        assert file_path.exists()
        parse_res = parser.parse_file(file_path)
        assert parse_res.success
        resources = sqlite_rule.detect_resources(parse_res.tree, file_path=str(file_path))
        assert len(resources) == 1
        assert resources[0].status == "SAFE"
        assert resources[0].resource_type == "SQLite connection"

