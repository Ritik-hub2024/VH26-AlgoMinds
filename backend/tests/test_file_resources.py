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
