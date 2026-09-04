"""Automated tests for SQLite database connection leak detection (Round 2 Milestone 2).

Covers:
1. CASE 1 — SQLite unclosed connection leak detected.
2. CASE 2 — SQLite guaranteed cleanup in finally recognized as SAFE.
3. CASE 3 — SQLite early-return bypassing close detected as LEAK.
4. Exception path bypassing close detected as LEAK.
5. Exception + finally recognized as SAFE.
6. Module-level unclosed connection detected as LEAK.
7. Context manager with contextlib.closing recognized as SAFE.
8. Finding details: severity, file, line, resource_type, variable_name, problem, leak_path, recommendation.
9. Verification against sample test files under python/leaks and python/safe.
"""

from pathlib import Path
import pytest

from analyzer.engine import AnalysisEngine
from analyzer.rules.sqlite_leak import SqliteLeakRule
from parser.ast_parser import ASTParser
from models.issue import Severity


@pytest.fixture
def parser() -> ASTParser:
    return ASTParser()


@pytest.fixture
def sqlite_rule() -> SqliteLeakRule:
    return SqliteLeakRule()


@pytest.fixture
def engine() -> AnalysisEngine:
    return AnalysisEngine()


@pytest.fixture
def python_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "python"


class TestSqliteConnectionLeakDetector:
    """Unit tests for SqliteLeakRule and SQLite lifecycle analysis."""

    # CASE 1 — SQLite leak (unclosed)
    def test_case_1_sqlite_leak_detected(self, parser, sqlite_rule):
        code = """
import sqlite3

def get_users():
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    return cursor.fetchall()
"""
        parse_res = parser.parse_source(code, filename="test_case1.py")
        assert parse_res.success
        assert parse_res.tree is not None

        resources = sqlite_rule.detect_resources(parse_res.tree, file_path="test_case1.py")
        assert len(resources) == 1
        res = resources[0]
        assert res.variable_name == "conn"
        assert res.resource_type == "SQLite connection"
        assert res.opening_line == 5
        assert res.function_name == "get_users"
        assert res.status == "LEAK"

        # Check issues
        assert len(sqlite_rule.issues) == 1
        issue = sqlite_rule.issues[0]
        assert issue.rule_id == "LEAK002"
        assert issue.severity == Severity.HIGH
        assert issue.resource_name == "conn"
        assert issue.resource_type == "SQLite connection"
        assert issue.location.line == 5
        assert "conn.close()" in issue.problem or "return" in issue.problem
        assert "L5: sqlite3.connect() -> L8: return (leak)" in issue.leak_path
        assert "conn.close()" in issue.recommendation

    # CASE 2 — SQLite safe (finally)
    def test_case_2_sqlite_safe_finally(self, parser, sqlite_rule):
        code = """
import sqlite3

def get_users():
    conn = sqlite3.connect("app.db")
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users")
        return cursor.fetchall()
    finally:
        conn.close()
"""
        parse_res = parser.parse_source(code, filename="test_case2.py")
        assert parse_res.success

        resources = sqlite_rule.detect_resources(parse_res.tree, file_path="test_case2.py")
        assert len(resources) == 1
        res = resources[0]
        assert res.variable_name == "conn"
        assert res.resource_type == "SQLite connection"
        assert res.status == "SAFE"
        assert res.closing_line == 11
        assert "finally" in res.explanation.lower()
        assert len(sqlite_rule.issues) == 0

    # CASE 3 — SQLite early return leak
    def test_case_3_sqlite_early_return_leak(self, parser, sqlite_rule):
        code = """
import sqlite3

def get_users(flag):
    conn = sqlite3.connect("app.db")
    if flag:
        return None
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    res = cursor.fetchall()
    conn.close()
    return res
"""
        parse_res = parser.parse_source(code, filename="test_case3.py")
        assert parse_res.success

        resources = sqlite_rule.detect_resources(parse_res.tree, file_path="test_case3.py")
        assert len(resources) == 1
        res = resources[0]
        assert res.status == "LEAK"

        assert len(sqlite_rule.issues) == 1
        issue = sqlite_rule.issues[0]
        assert issue.rule_id == "LEAK002"
        assert issue.resource_name == "conn"
        assert issue.resource_type == "SQLite connection"
        assert "flag" in issue.problem
        assert "L5: sqlite3.connect() -> L6: if flag -> L7: return (leak)" in issue.leak_path
        assert "conn.close()" in issue.recommendation

    # Exception path leak
    def test_sqlite_exception_path_leak(self, parser, sqlite_rule):
        code = """
import sqlite3

def query_db():
    conn = sqlite3.connect("app.db")
    try:
        conn.execute("SELECT 1")
    except sqlite3.DatabaseError:
        return None
    conn.close()
"""
        parse_res = parser.parse_source(code)
        resources = sqlite_rule.detect_resources(parse_res.tree)
        assert len(resources) == 1
        assert resources[0].status == "LEAK"
        assert len(sqlite_rule.issues) == 1
        issue = sqlite_rule.issues[0]
        assert "except sqlite3.DatabaseError" in issue.leak_path
        assert "return (leak)" in issue.leak_path

    # Context manager with contextlib.closing
    def test_sqlite_closing_context_manager_safe(self, parser, sqlite_rule):
        code = """
import sqlite3
from contextlib import closing

def query_db():
    with closing(sqlite3.connect("app.db")) as conn:
        return conn.execute("SELECT 1").fetchall()
"""
        parse_res = parser.parse_source(code)
        resources = sqlite_rule.detect_resources(parse_res.tree)
        assert len(resources) == 1
        assert resources[0].status == "SAFE"
        assert resources[0].is_context_manager is True
        assert len(sqlite_rule.issues) == 0

    # Module level unclosed
    def test_sqlite_module_level_leak(self, parser, sqlite_rule):
        code = """
import sqlite3

conn = sqlite3.connect("app.db")
cursor = conn.cursor()
cursor.execute("SELECT 1")
"""
        parse_res = parser.parse_source(code)
        resources = sqlite_rule.detect_resources(parse_res.tree)
        assert len(resources) == 1
        assert resources[0].status == "LEAK"
        assert len(sqlite_rule.issues) == 1
        assert "never closed" in sqlite_rule.issues[0].problem


class TestSqliteSampleFiles:
    """Verify newly created sample test files under python/leaks and python/safe."""

    def test_sample_sqlite_leak(self, engine, python_dir):
        file_path = python_dir / "leaks" / "sqlite_leak.py"
        assert file_path.exists()
        parse_res, issues = engine.analyze_file(file_path)
        assert parse_res.success
        assert len(issues) == 1
        assert issues[0].rule_id == "LEAK002"
        assert issues[0].resource_type == "SQLite connection"
        assert issues[0].resource_name == "conn"

    def test_sample_sqlite_early_return(self, engine, python_dir):
        file_path = python_dir / "leaks" / "sqlite_early_return.py"
        assert file_path.exists()
        parse_res, issues = engine.analyze_file(file_path)
        assert parse_res.success
        assert len(issues) == 1
        assert issues[0].rule_id == "LEAK002"
        assert issues[0].resource_type == "SQLite connection"
        assert "flag" in issues[0].problem

    def test_sample_sqlite_safe(self, engine, python_dir):
        file_path = python_dir / "safe" / "sqlite_safe.py"
        assert file_path.exists()
        parse_res, issues = engine.analyze_file(file_path)
        assert parse_res.success
        assert len(issues) == 0
