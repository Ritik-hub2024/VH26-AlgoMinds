"""Tests for basic file resource leak detection (Step 02)."""

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


def test_01_file_no_close_leaks(analyzer, python_dir):
    """Verify python/01_file_no_close.py is detected as LEAK."""
    target = python_dir / "01_file_no_close.py"
    assert target.exists()

    res, resources = analyzer.analyze_file(target)
    assert res.success
    assert len(resources) == 1
    assert resources[0].variable_name == "f"
    assert resources[0].resource_type == "file"
    assert resources[0].status == "LEAK"
    assert resources[0].opening_line == 6


def test_10_normal_close_is_safe(analyzer, python_dir):
    """Verify python/10_normal_close.py is detected as SAFE."""
    target = python_dir / "10_normal_close.py"
    assert target.exists()

    res, resources = analyzer.analyze_file(target)
    assert res.success
    assert len(resources) == 1
    assert resources[0].variable_name == "f"
    assert resources[0].status == "SAFE"
    assert resources[0].closing_line == 8


def test_inline_open_and_close_safe(analyzer, parser):
    code = """
def run():
    f = open("log.txt")
    data = f.read()
    f.close()
    return data
"""
    res = parser.parse_source(code)
    resources = analyzer.analyze_tree(res.tree)
    assert len(resources) == 1
    assert resources[0].status == "SAFE"


def test_inline_open_no_close_leaks(analyzer, parser):
    code = """
def run():
    f = open("log.txt")
    return f.read()
"""
    res = parser.parse_source(code)
    resources = analyzer.analyze_tree(res.tree)
    assert len(resources) == 1
    assert resources[0].status == "LEAK"


def test_exception_path_early_return_leaks(analyzer, parser):
    code = """
def run():
    f = open("log.txt")
    try:
        return f.read()
    except ValueError:
        return "DEFAULT"
    f.close()
"""
    res = parser.parse_source(code)
    resources = analyzer.analyze_tree(res.tree)
    assert len(resources) == 1
    assert resources[0].status == "LEAK"
    assert "except ValueError" in resources[0].leak_path
    assert "return (leak)" in resources[0].leak_path


def test_finally_close_is_safe(analyzer, parser):
    code = """
def run():
    f = open("log.txt")
    try:
        return f.read()
    except ValueError:
        return "DEFAULT"
    finally:
        f.close()
"""
    res = parser.parse_source(code)
    resources = analyzer.analyze_tree(res.tree)
    assert len(resources) == 1
    assert resources[0].status == "SAFE"


def test_leak_exception_sample_file(analyzer, python_dir):
    target = python_dir / "leak_exception.py"
    assert target.exists()
    res, resources = analyzer.analyze_file(target)
    assert res.success
    assert len(resources) == 1
    assert resources[0].status == "LEAK"
    assert "except ValueError" in resources[0].leak_path


def test_safe_finally_sample_file(analyzer, python_dir):
    target = python_dir / "safe_finally.py"
    assert target.exists()
    res, resources = analyzer.analyze_file(target)
    assert res.success
    assert len(resources) == 1
    assert resources[0].status == "SAFE"


def test_sqlite_leak_sample_file(analyzer, python_dir):
    target = python_dir / "leaks" / "sqlite_leak.py"
    assert target.exists()
    res, resources = analyzer.analyze_file(target)
    assert res.success
    assert len(resources) == 1
    assert resources[0].status == "LEAK"
    assert resources[0].resource_type == "SQLite connection"


def test_sqlite_safe_sample_file(analyzer, python_dir):
    target = python_dir / "safe" / "sqlite_safe.py"
    assert target.exists()
    res, resources = analyzer.analyze_file(target)
    assert res.success
    assert len(resources) == 1
    assert resources[0].status == "SAFE"
    assert resources[0].resource_type == "SQLite connection"


