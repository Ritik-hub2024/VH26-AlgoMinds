"""Tests for control-flow analysis, early returns, and with context manager (Step 03)."""

from pathlib import Path
import pytest
from leakguard.analyzer.leak_analyzer import LeakAnalyzer
from leakguard.parser.python_parser import PythonParser


@pytest.fixture
def analyzer():
    return LeakAnalyzer()


@pytest.fixture
def parser():
    return PythonParser()


@pytest.fixture
def python_dir():
    return Path(__file__).resolve().parent.parent.parent / "python"


def test_02_file_early_return_leaks(analyzer, python_dir):
    """Verify python/02_file_early_return.py detects open -> if condition -> return -> close."""
    target = python_dir / "02_file_early_return.py"
    assert target.exists()

    res, resources = analyzer.analyze_file(target)
    assert res.success
    assert len(resources) == 1
    r = resources[0]
    assert r.status == "LEAK"
    assert r.variable_name == "f"
    assert r.opening_line == 9
    assert "skip" in r.explanation
    assert "L9: open() -> L11: if skip -> L13: return (leak)" in r.leak_path


def test_04_file_with_is_safe(analyzer, python_dir):
    """Verify python/04_file_with.py recognizes with open(...) as safe context manager."""
    target = python_dir / "04_file_with.py"
    assert target.exists()

    res, resources = analyzer.analyze_file(target)
    assert res.success
    assert len(resources) == 1
    r = resources[0]
    assert r.status == "SAFE"
    assert r.is_context_manager is True


def test_early_return_inside_with_is_safe(analyzer, parser):
    """Early return inside a with block is safe because __exit__ always runs."""
    code = """
def fetch(path, condition):
    with open(path) as f:
        if condition:
            return "EXIT"
        return f.read()
"""
    res = parser.parse_source(code)
    resources = analyzer.analyze_tree(res.tree)
    assert len(resources) == 1
    assert resources[0].status == "SAFE"


def test_branch_asymmetric_leak(analyzer, parser):
    """Detect leak when if branch closes but else branch returns early."""
    code = """
def test_branch(path, flag):
    f = open(path)
    if flag:
        f.close()
        return "SAFE"
    else:
        return "LEAK"
"""
    res = parser.parse_source(code)
    resources = analyzer.analyze_tree(res.tree)
    assert len(resources) == 1
    assert resources[0].status == "LEAK"
    assert "else" in resources[0].leak_path
