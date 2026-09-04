"""Automated tests for FileLeakRule AST resource leak detector."""

import ast
from pathlib import Path
import pytest

from analyzer.rules.file_leak import FileLeakRule
from models.resource import Resource
from parser.ast_parser import ASTParser


@pytest.fixture
def parser() -> ASTParser:
    return ASTParser()


@pytest.fixture
def rule() -> FileLeakRule:
    return FileLeakRule()


class TestResourceModel:
    """Test Resource object structure and fields."""

    def test_resource_fields(self):
        res = Resource(
            variable_name="f",
            resource_type="file",
            opening_line=12,
            function_name="load_data",
            status="SAFE",
            closing_line=15,
            explanation="Closed via 'f.close()'.",
            leak_path=None,
            is_context_manager=False,
        )
        assert res.variable_name == "f"
        assert res.resource_type == "file"
        assert res.opening_line == 12
        assert res.function_name == "load_data"
        assert res.status == "SAFE"
        assert res.closing_line == 15
        assert not res.is_context_manager

        d = res.to_dict()
        assert d["variable_name"] == "f"
        assert d["resource_type"] == "file"
        assert d["opening_line"] == 12
        assert d["function_name"] == "load_data"
        assert d["status"] == "SAFE"
        assert d["closing_line"] == 15
        assert d["is_context_manager"] is False


class TestASTLeakDetector:
    """Test AST detection with control-flow analysis and context managers."""

    def test_simple_function_open_and_close_is_safe(self, parser, rule):
        code = """
def process_file():
    f = open("data.txt")
    data = f.read()
    f.close()
    return data
"""
        parse_res = parser.parse_source(code, filename="test_safe.py")
        assert parse_res.success
        assert parse_res.tree is not None

        resources = rule.detect_resources(parse_res.tree, file_path="test_safe.py")
        assert len(resources) == 1
        res = resources[0]
        assert res.variable_name == "f"
        assert res.resource_type == "file"
        assert res.opening_line == 3
        assert res.function_name == "process_file"
        assert res.status == "SAFE"
        assert res.closing_line == 5
        assert len(rule.issues) == 0

    def test_with_open_is_safe(self, parser, rule):
        """Verify that 'with open(...) as f:' is recognized as a safe context manager."""
        code = """
def read_with_context(path):
    with open(path, "r") as f:
        return f.read()
"""
        parse_res = parser.parse_source(code, filename="test_with.py")
        assert parse_res.success

        resources = rule.detect_resources(parse_res.tree, file_path="test_with.py")
        assert len(resources) == 1
        res = resources[0]
        assert res.variable_name == "f"
        assert res.status == "SAFE"
        assert res.is_context_manager is True
        assert len(rule.issues) == 0

    def test_with_open_early_return_is_safe(self, parser, rule):
        """Verify that early returns inside with-blocks are safe because __exit__ always runs."""
        code = """
def read_with_early_exit(path, flag):
    with open(path) as f:
        if flag:
            return "Early exit"
        return f.read()
"""
        parse_res = parser.parse_source(code)
        resources = rule.detect_resources(parse_res.tree)
        assert len(resources) == 1
        assert resources[0].status == "SAFE"
        assert len(rule.issues) == 0

    def test_open_if_condition_return_close_pattern(self, parser, rule):
        """Detect the required jury pattern: open -> if condition -> return -> close."""
        code = """
def parse_header_or_skip(filename, skip):
    f = open(filename, "r")
    if skip:
        return "SKIPPED"
    header = f.readline()
    f.close()
    return header
"""
        parse_res = parser.parse_source(code, filename="jury_sample.py")
        resources = rule.detect_resources(parse_res.tree, file_path="jury_sample.py")
        assert len(resources) == 1
        assert resources[0].status == "LEAK"

        # Check actionable issue fields
        assert len(rule.issues) == 1
        issue = rule.issues[0]
        assert issue.rule_id == "LEAK001"
        assert issue.resource_name == "f"
        assert issue.resource_type == "file"
        assert issue.location.line == 3
        assert "skip" in issue.problem
        assert "L3: open() -> L4: if skip -> L5: return (leak)" in issue.leak_path
        assert "with open" in issue.recommendation

    def test_simple_function_open_without_close_is_leak(self, parser, rule):
        code = """
def leak_data():
    f = open("data.txt")
    data = f.read()
    return data
"""
        parse_res = parser.parse_source(code, filename="test_leak.py")
        resources = rule.detect_resources(parse_res.tree, file_path="test_leak.py")
        assert len(resources) == 1
        assert resources[0].status == "LEAK"
        assert len(rule.issues) == 1
        issue = rule.issues[0]
        assert issue.resource_name == "f"
        assert issue.location.line == 3

    def test_try_finally_is_safe(self, parser, rule):
        code = """
def safe_finally():
    f = open("important.dat")
    try:
        data = f.read()
        return data
    finally:
        f.close()
"""
        parse_res = parser.parse_source(code)
        resources = rule.detect_resources(parse_res.tree)
        assert len(resources) == 1
        assert resources[0].status == "SAFE"
        assert len(rule.issues) == 0

    def test_if_else_both_close_is_safe(self, parser, rule):
        code = """
def branch_both_safe(flag):
    f = open("data.bin")
    if flag:
        data = f.read(10)
        f.close()
        return data
    else:
        data = f.read(20)
        f.close()
        return data
"""
        parse_res = parser.parse_source(code)
        resources = rule.detect_resources(parse_res.tree)
        assert len(resources) == 1
        assert resources[0].status == "SAFE"
        assert len(rule.issues) == 0

    def test_if_else_one_branch_leaks(self, parser, rule):
        code = """
def branch_asymmetric(flag):
    f = open("data.bin")
    if flag:
        data = f.read(10)
        f.close()
        return data
    else:
        return "FAILED"
"""
        parse_res = parser.parse_source(code)
        resources = rule.detect_resources(parse_res.tree)
        assert len(resources) == 1
        assert resources[0].status == "LEAK"
        assert len(rule.issues) == 1
        assert "else" in rule.issues[0].leak_path

    def test_try_except_early_return_is_leak(self, parser, rule):
        """Verify that early return inside an except handler is flagged as an exception path leak."""
        code = """
def parse_record(path):
    f = open(path, "r")
    try:
        data = f.read()
    except ValueError:
        return "DEFAULT"
    f.close()
    return data
"""
        parse_res = parser.parse_source(code)
        resources = rule.detect_resources(parse_res.tree)
        assert len(resources) == 1
        assert resources[0].status == "LEAK"
        assert len(rule.issues) == 1
        issue = rule.issues[0]
        assert issue.resource_name == "f"
        assert "except ValueError" in issue.leak_path
        assert "return (leak)" in issue.leak_path
        assert "except ValueError" in issue.problem

    def test_try_except_raise_is_leak(self, parser, rule):
        """Verify that raise inside an except handler is flagged as an exception path leak."""
        code = """
def parse_record(path):
    f = open(path, "r")
    try:
        data = f.read()
    except OSError:
        raise
    f.close()
    return data
"""
        parse_res = parser.parse_source(code)
        resources = rule.detect_resources(parse_res.tree)
        assert len(resources) == 1
        assert resources[0].status == "LEAK"
        assert len(rule.issues) == 1
        issue = rule.issues[0]
        assert "except OSError" in issue.leak_path
        assert "raise (leak)" in issue.leak_path

    def test_try_finally_with_except_is_safe(self, parser, rule):
        """Verify that close in finally block ensures safety even when except returns early."""
        code = """
def parse_record_safe(path):
    f = open(path, "r")
    try:
        data = f.read()
        return data
    except ValueError:
        return "DEFAULT"
    finally:
        f.close()
"""
        parse_res = parser.parse_source(code)
        resources = rule.detect_resources(parse_res.tree)
        assert len(resources) == 1
        assert resources[0].status == "SAFE"
        assert len(rule.issues) == 0

    def test_open_inside_try_with_finally_is_safe(self, parser, rule):
        """Verify that open() inside try with f.close() in finally is safe."""
        code = """
def load_inside_try(path):
    try:
        f = open(path, "r")
        return f.read()
    finally:
        f.close()
"""
        parse_res = parser.parse_source(code)
        resources = rule.detect_resources(parse_res.tree)
        assert len(resources) == 1
        assert resources[0].status == "SAFE"
        assert len(rule.issues) == 0

    def test_try_close_without_finally_is_leak(self, parser, rule):
        """Verify that close() only inside try body without finally leaks if exceptions occur."""
        code = """
def close_only_in_try(path):
    f = open(path, "r")
    try:
        data = f.read()
        f.close()
    except ValueError:
        pass
"""
        parse_res = parser.parse_source(code)
        resources = rule.detect_resources(parse_res.tree)
        assert len(resources) == 1
        assert resources[0].status == "LEAK"
        assert len(rule.issues) == 1
        assert "try (exception path leaks)" in rule.issues[0].leak_path


class TestSampleFilesUnderPython:
    """Validate detector behavior against all sample files in python/."""

    @pytest.fixture
    def python_dir(self) -> Path:
        return Path(__file__).resolve().parent.parent / "python"

    def test_safe_file_py(self, parser, rule, python_dir):
        file_path = python_dir / "safe_file.py"
        parse_res = parser.parse_file(file_path)
        assert parse_res.success
        resources = rule.detect_resources(parse_res.tree, file_path=str(file_path))
        assert len(resources) == 1
        assert resources[0].status == "SAFE"
        assert len(rule.issues) == 0

    def test_safe_try_finally_py(self, parser, rule, python_dir):
        file_path = python_dir / "safe_try_finally.py"
        parse_res = parser.parse_file(file_path)
        assert parse_res.success
        resources = rule.detect_resources(parse_res.tree, file_path=str(file_path))
        assert len(resources) == 1
        assert resources[0].status == "SAFE"
        assert len(rule.issues) == 0

    def test_safe_finally_py(self, parser, rule, python_dir):
        file_path = python_dir / "safe_finally.py"
        parse_res = parser.parse_file(file_path)
        assert parse_res.success
        resources = rule.detect_resources(parse_res.tree, file_path=str(file_path))
        assert len(resources) == 1
        assert resources[0].status == "SAFE"
        assert len(rule.issues) == 0

    def test_safe_with_py(self, parser, rule, python_dir):
        file_path = python_dir / "safe_with.py"
        parse_res = parser.parse_file(file_path)
        assert parse_res.success
        resources = rule.detect_resources(parse_res.tree, file_path=str(file_path))
        assert len(resources) == 1
        assert resources[0].status == "SAFE"
        assert resources[0].is_context_manager is True
        assert len(rule.issues) == 0

    def test_safe_with_early_return_py(self, parser, rule, python_dir):
        file_path = python_dir / "safe_with_early_return.py"
        parse_res = parser.parse_file(file_path)
        assert parse_res.success
        resources = rule.detect_resources(parse_res.tree, file_path=str(file_path))
        assert len(resources) == 1
        assert resources[0].status == "SAFE"
        assert len(rule.issues) == 0

    def test_leak_file_py(self, parser, rule, python_dir):
        file_path = python_dir / "leak_file.py"
        parse_res = parser.parse_file(file_path)
        assert parse_res.success
        resources = rule.detect_resources(parse_res.tree, file_path=str(file_path))
        assert len(resources) == 1
        assert resources[0].status == "LEAK"
        assert len(rule.issues) == 1

    def test_leak_early_return_py(self, parser, rule, python_dir):
        file_path = python_dir / "leak_early_return.py"
        parse_res = parser.parse_file(file_path)
        assert parse_res.success
        resources = rule.detect_resources(parse_res.tree, file_path=str(file_path))
        assert len(resources) == 1
        assert resources[0].status == "LEAK"
        assert len(rule.issues) == 1

        issue = rule.issues[0]
        assert issue.location.line == 10
        assert issue.resource_name == "f"
        assert "L10: open() -> L12: if skip -> L14: return (leak)" in issue.leak_path
        assert "with open" in issue.recommendation

    def test_leak_if_else_py(self, parser, rule, python_dir):
        file_path = python_dir / "leak_if_else.py"
        parse_res = parser.parse_file(file_path)
        assert parse_res.success
        resources = rule.detect_resources(parse_res.tree, file_path=str(file_path))
        assert len(resources) == 1
        assert resources[0].status == "LEAK"
        assert len(rule.issues) == 1
        assert "else" in rule.issues[0].leak_path

    def test_leak_exception_py(self, parser, rule, python_dir):
        file_path = python_dir / "leak_exception.py"
        parse_res = parser.parse_file(file_path)
        assert parse_res.success
        resources = rule.detect_resources(parse_res.tree, file_path=str(file_path))
        assert len(resources) == 1
        assert resources[0].status == "LEAK"
        assert len(rule.issues) == 1
        assert "except ValueError" in rule.issues[0].leak_path
        assert "return (leak)" in rule.issues[0].leak_path
