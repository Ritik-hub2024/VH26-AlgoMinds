"""Unit tests for LeakGuard Fix Engine, AST patch generator, and validator."""

from pathlib import Path
import pytest

from fixers.validator import validate_python_syntax
from fixers.patch_generator import generate_unified_diff, generate_diff_chunks
from fixers.resource_fixer import ResourceFixer
from fixers.engine import RemediationEngine


def test_validator_valid_code():
    code = "def sample():\n    return 42\n"
    is_valid, err = validate_python_syntax(code)
    assert is_valid is True
    assert err is None


def test_validator_invalid_code():
    code = "def sample():\n    return (\n"
    is_valid, err = validate_python_syntax(code)
    assert is_valid is False
    assert "Syntax error" in err


def test_patch_generator_diff():
    orig = "def foo():\n    f = open('data.txt')\n    return f.read()\n"
    mod = "def foo():\n    with open('data.txt') as f:\n        return f.read()\n"
    diff_data = generate_diff_chunks(orig, mod, filename="test.py")

    assert diff_data["additions"] >= 1
    assert diff_data["deletions"] >= 1
    assert "with open('data.txt') as f:" in diff_data["unified_diff"]


def test_resource_fixer_file_leak():
    fixer = ResourceFixer()
    code = """def load_file(path):
    f = open(path, "r")
    data = f.read()
    return data
"""
    finding = {
        "rule_id": "LEAK001",
        "file": "test.py",
        "line": 2,
        "variable": "f",
        "resource": "f (file)",
        "classification": "LEAK",
        "ownership_status": "LOCAL",
    }

    assert fixer.can_fix(finding) is True
    success, fixed_code, err = fixer.generate_fix(code, finding)
    assert success is True
    assert fixed_code is not None
    assert "with open(path, \"r\") as f:" in fixed_code
    assert "data = f.read()" in fixed_code
    assert validate_python_syntax(fixed_code)[0] is True


def test_resource_fixer_sqlite_leak():
    fixer = ResourceFixer()
    code = """import sqlite3

def fetch_users():
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT 1")
    return cursor.fetchall()
"""
    finding = {
        "rule_id": "LEAK002",
        "file": "db.py",
        "line": 4,
        "variable": "conn",
        "resource": "conn (sqlite3)",
        "classification": "LEAK",
        "ownership_status": "LOCAL",
    }

    assert fixer.can_fix(finding) is True
    success, fixed_code, err = fixer.generate_fix(code, finding)
    assert success is True
    assert "try:" in fixed_code
    assert "finally:" in fixed_code
    assert "conn.close()" in fixed_code
    assert validate_python_syntax(fixed_code)[0] is True


def test_resource_fixer_rejects_unsupported_transferred_ownership():
    fixer = ResourceFixer()
    finding = {
        "rule_id": "LEAK001",
        "file": "caller.py",
        "line": 5,
        "classification": "UNKNOWN",
        "ownership_status": "TRANSFERRED",
    }
    assert fixer.can_fix(finding) is False
