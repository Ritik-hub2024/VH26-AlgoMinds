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

    # SUPPORTED CASE 2 — SQLite explicit close
    def test_case_2_sqlite_explicit_close_safe(self, parser, sqlite_rule):
        code = """
import sqlite3

def get_users():
    conn = sqlite3.connect("app.db")
    data = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    return data
"""
        parse_res = parser.parse_source(code, filename="test_explicit_close.py")
        assert parse_res.success
        resources = sqlite_rule.detect_resources(parse_res.tree, file_path="test_explicit_close.py")
        assert len(resources) == 1
        assert resources[0].status == "SAFE"
        assert resources[0].closing_line == 7
        assert len(sqlite_rule.issues) == 0

    # SUPPORTED CASE 6 — SQLite exception + finally
    def test_case_6_sqlite_exception_plus_finally_safe(self, parser, sqlite_rule):
        code = """
import sqlite3

def get_users():
    conn = sqlite3.connect("app.db")
    try:
        risky_operation()
    except Exception:
        return None
    finally:
        conn.close()
"""
        parse_res = parser.parse_source(code, filename="test_exc_finally.py")
        assert parse_res.success
        resources = sqlite_rule.detect_resources(parse_res.tree, file_path="test_exc_finally.py")
        assert len(resources) == 1
        assert resources[0].status == "SAFE"
        assert len(sqlite_rule.issues) == 0

    # Exact verification of Milestone 2 Cases 1 through 6
    def test_exact_milestone_cases_1_through_6(self, parser):
        # CASE 1 — SQLite Leak
        case1 = """
import sqlite3

def get_users():
    conn = sqlite3.connect("app.db")
    return conn.execute("SELECT * FROM users").fetchall()
"""
        rule1 = SqliteLeakRule()
        res1 = rule1.detect_resources(parser.parse_source(case1).tree)
        assert res1[0].status == "LEAK"
        assert len(rule1.issues) == 1
        assert "L6: return (leak)" in rule1.issues[0].leak_path

        # CASE 2 — SQLite Explicit Close
        case2 = """
import sqlite3

def get_users():
    conn = sqlite3.connect("app.db")
    data = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    return data
"""
        rule2 = SqliteLeakRule()
        res2 = rule2.detect_resources(parser.parse_source(case2).tree)
        assert res2[0].status == "SAFE"
        assert len(rule2.issues) == 0

        # CASE 3 — SQLite Early Return
        case3 = """
import sqlite3

def get_users(error):
    conn = sqlite3.connect("app.db")

    if error:
        return None

    conn.close()
    return []
"""
        rule3 = SqliteLeakRule()
        res3 = rule3.detect_resources(parser.parse_source(case3).tree)
        assert res3[0].status == "LEAK"
        assert len(rule3.issues) == 1
        assert "if error" in rule3.issues[0].leak_path
        assert "return (leak)" in rule3.issues[0].leak_path

        # CASE 4 — SQLite Finally
        case4 = """
import sqlite3

def get_users():
    conn = sqlite3.connect("app.db")

    try:
        return conn.execute("SELECT * FROM users").fetchall()
    finally:
        conn.close()
"""
        rule4 = SqliteLeakRule()
        res4 = rule4.detect_resources(parser.parse_source(case4).tree)
        assert res4[0].status == "SAFE"
        assert len(rule4.issues) == 0

        # CASE 5 — SQLite Exception Path
        case5 = """
import sqlite3

def get_users():
    conn = sqlite3.connect("app.db")

    try:
        risky_operation()
    except Exception:
        return None

    conn.close()
"""
        rule5 = SqliteLeakRule()
        res5 = rule5.detect_resources(parser.parse_source(case5).tree)
        assert res5[0].status == "LEAK"
        assert len(rule5.issues) == 1
        assert "except Exception" in rule5.issues[0].leak_path
        assert "return (leak)" in rule5.issues[0].leak_path

        # CASE 6 — SQLite Exception + Finally
        case6 = """
import sqlite3

def get_users():
    conn = sqlite3.connect("app.db")

    try:
        risky_operation()
    except Exception:
        return None
    finally:
        conn.close()
"""
        rule6 = SqliteLeakRule()
        res6 = rule6.detect_resources(parser.parse_source(case6).tree)
        assert res6[0].status == "SAFE"
        assert len(rule6.issues) == 0

    # Finding output dimensions
    def test_sqlite_finding_output_dimensions(self, parser, sqlite_rule):
        code = """
import sqlite3

def get_users():
    conn = sqlite3.connect("app.db")
    return conn.execute("SELECT * FROM users").fetchall()
"""
        parse_res = parser.parse_source(code, filename="python/leaks/sqlite_leak.py")
        sqlite_rule.detect_resources(parse_res.tree, file_path="python/leaks/sqlite_leak.py")
        assert len(sqlite_rule.issues) == 1
        issue = sqlite_rule.issues[0]
        d = issue.to_dict()

        assert d["severity"] == "HIGH"
        assert d["file"] == "python/leaks/sqlite_leak.py"
        assert d["line"] == 5
        assert d["opened_line"] == 5
        assert d["resource"] == "conn (SQLite connection)"
        assert d["variable"] == "conn"
        assert "SQLite connection" in d["reason"]
        assert "sqlite3.connect()" in d["path"] and "return (leak)" in d["path"]
        assert d["cleanup_status"] == "UNCLOSED"
        assert "conn.close()" in d["recommendation"]

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
