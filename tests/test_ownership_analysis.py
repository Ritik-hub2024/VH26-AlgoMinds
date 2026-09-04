"""Comprehensive automated tests for Step 8: Resource Ownership, Reassignment & Alias Analysis.

Guarantees:
- Phase 1: Reassignments (overwritten without close -> LEAK; closed before reassignment -> SAFE)
- Phase 2: Local aliases (closing alias frees original -> SAFE; neither closed -> LEAK)
- Phase 3: Argument transfer (passing to external function -> UNKNOWN / TRANSFERRED)
- Phase 4: Callee proof (intra-module callee unconditionally closes -> SAFE; partial/no close -> UNKNOWN)
- Phase 5: Returned resources (returning resource -> UNKNOWN / RETURNED; return f.read() -> LEAK)
- Phase 6: Attribute storage (self.f = open() -> UNKNOWN / ATTRIBUTE; self.f.close() -> SAFE)
- Phase 7: Container escapes (list.append(f) -> UNKNOWN / CONTAINER)
- Phase 8: Policy gating (--block-unknown blocks UNKNOWN; default is advisory warning)
- Phase 9: Zero code execution guarantee
"""

import ast
import pytest
from pathlib import Path
from typing import List

from analyzer.engine import AnalysisEngine
from analyzer.rules.base_lifecycle import BaseResourceLifecycleRule
from analyzer.rules.file_leak import FileLeakRule
from analyzer.rules.sqlite_leak import SqliteLeakRule
from models.issue import LeakIssue, Severity, SourceLocation
from models.policy import SecurityPolicy
from models.report import AnalysisReport
from cli import scan_target, main


@pytest.fixture
def engine():
    return AnalysisEngine()


def analyze_snippet(engine: AnalysisEngine, code: str) -> List[LeakIssue]:
    tree = ast.parse(code)
    return engine.analyze_tree(tree, "test_snippet.py")


# =============================================================================
# Phase 1: Reassignments
# =============================================================================

def test_reassignment_leak(engine):
    code = """
def test_reassign():
    f = open("file1.txt", "w")
    f = open("file2.txt", "w")  # Overwrites f without closing first handle
    f.close()
"""
    issues = analyze_snippet(engine, code)
    assert len(issues) == 1
    issue = issues[0]
    assert issue.classification == "LEAK"
    assert issue.ownership_status == "REASSIGNED"
    assert "reassigned" in issue.problem.lower() or "overwritten" in issue.problem.lower()
    assert issue.location.line == 3


def test_reassignment_safe(engine):
    code = """
def test_reassign_safe():
    f = open("file1.txt", "w")
    f.close()
    f = open("file2.txt", "w")
    f.close()
"""
    issues = analyze_snippet(engine, code)
    assert len(issues) == 0


def test_reassignment_multiple_leaks(engine):
    code = """
def test_multiple_reassign():
    f = open("file1.txt", "w")
    f = open("file2.txt", "w")  # leak 1
    f = open("file3.txt", "w")  # leak 2
    # leak 3 (never closed)
"""
    issues = analyze_snippet(engine, code)
    assert len(issues) == 3
    reassigned = [i for i in issues if i.ownership_status == "REASSIGNED"]
    assert len(reassigned) == 2


# =============================================================================
# Phase 2: Local Aliases
# =============================================================================

def test_alias_closed_via_alias_is_safe(engine):
    code = """
def test_alias_safe():
    f = open("data.txt", "r")
    g = f
    g.close()
"""
    issues = analyze_snippet(engine, code)
    assert len(issues) == 0


def test_alias_closed_via_original_is_safe(engine):
    code = """
def test_alias_safe_orig():
    f = open("data.txt", "r")
    g = f
    f.close()
"""
    issues = analyze_snippet(engine, code)
    assert len(issues) == 0


def test_alias_neither_closed_is_leak(engine):
    code = """
def test_alias_leak():
    f = open("data.txt", "r")
    g = f
    return 100
"""
    issues = analyze_snippet(engine, code)
    assert len(issues) == 1
    assert issues[0].classification == "LEAK"


def test_transitive_alias_safe(engine):
    code = """
def test_transitive():
    f = open("data.txt", "r")
    g = f
    h = g
    h.close()
"""
    issues = analyze_snippet(engine, code)
    assert len(issues) == 0


# =============================================================================
# Phase 3: Argument Transfers
# =============================================================================

def test_argument_transfer_unprovable_is_unknown(engine):
    code = """
def test_transfer():
    f = open("data.txt", "r")
    external_library_func(f)
"""
    issues = analyze_snippet(engine, code)
    assert len(issues) == 1
    issue = issues[0]
    assert issue.classification == "UNKNOWN"
    assert issue.ownership_status == "TRANSFERRED"
    assert issue.callee_name == "external_library_func"
    assert issue.transfer_line == 4
    assert issue.severity == Severity.LOW
    assert "interprocedural" in issue.scope_limitation.lower() or "escaped" in issue.scope_limitation.lower()


def test_argument_transfer_with_read_is_not_transfer(engine):
    # Calling external_func(f.read()) does NOT transfer ownership of f!
    code = """
def test_not_transfer():
    f = open("data.txt", "r")
    external_func(f.read())
    # f is not closed!
"""
    issues = analyze_snippet(engine, code)
    assert len(issues) == 1
    issue = issues[0]
    # This must be a LEAK, NOT UNKNOWN, because f itself was not passed!
    assert issue.classification == "LEAK"


# =============================================================================
# Phase 4: Callee Proof
# =============================================================================

def test_callee_closes_unconditionally_is_safe(engine):
    code = """
def closer(handle):
    handle.close()

def caller():
    f = open("data.txt", "w")
    closer(f)
"""
    issues = analyze_snippet(engine, code)
    assert len(issues) == 0


def test_callee_does_not_close_is_unknown(engine):
    code = """
def no_close(handle):
    pass

def caller():
    f = open("data.txt", "w")
    no_close(f)
"""
    issues = analyze_snippet(engine, code)
    assert len(issues) == 1
    issue = issues[0]
    assert issue.classification == "UNKNOWN"
    assert issue.ownership_status == "TRANSFERRED"
    assert issue.callee_name == "no_close"


def test_callee_closes_only_on_one_branch_is_unknown(engine):
    code = """
def partial_close(handle, flag):
    if flag:
        handle.close()

def caller():
    f = open("data.txt", "w")
    partial_close(f, True)
"""
    issues = analyze_snippet(engine, code)
    assert len(issues) == 1
    issue = issues[0]
    assert issue.classification == "UNKNOWN"
    assert issue.ownership_status == "TRANSFERRED"


def test_callee_with_unclosed_early_return_is_unknown(engine):
    code = """
def flawed_closer(handle, error):
    if error:
        return
    handle.close()

def caller():
    f = open("data.txt", "w")
    flawed_closer(f, False)
"""
    issues = analyze_snippet(engine, code)
    assert len(issues) == 1
    assert issues[0].classification == "UNKNOWN"


# =============================================================================
# Phase 5: Returned Resources
# =============================================================================

def test_returned_resource_is_unknown(engine):
    code = """
def get_resource():
    f = open("stream.dat", "rb")
    return f
"""
    issues = analyze_snippet(engine, code)
    assert len(issues) == 1
    issue = issues[0]
    assert issue.classification == "UNKNOWN"
    assert issue.ownership_status == "RETURNED"
    assert issue.severity == Severity.LOW


def test_returned_resource_in_tuple_is_unknown(engine):
    code = """
def get_pair():
    f = open("stream.dat", "rb")
    return f, "metadata"
"""
    issues = analyze_snippet(engine, code)
    assert len(issues) == 1
    assert issues[0].classification == "UNKNOWN"
    assert issues[0].ownership_status == "RETURNED"


def test_return_method_call_is_leak_not_returned(engine):
    code = """
def read_data():
    f = open("stream.dat", "rb")
    return f.read()  # f itself is NOT returned; handle is leaked
"""
    issues = analyze_snippet(engine, code)
    assert len(issues) == 1
    assert issues[0].classification == "LEAK"


# =============================================================================
# Phase 6: Attribute Storage
# =============================================================================

def test_attribute_storage_is_unknown(engine):
    code = """
class MyHandler:
    def __init__(self):
        self.file = open("log.txt", "w")
"""
    issues = analyze_snippet(engine, code)
    assert len(issues) == 1
    issue = issues[0]
    assert issue.classification == "UNKNOWN"
    assert issue.ownership_status == "ATTRIBUTE"
    assert "attribute" in issue.problem.lower()


def test_attribute_closed_in_same_scope_is_safe(engine):
    code = """
class MyHandler:
    def execute(self):
        self.file = open("log.txt", "w")
        self.file.close()
"""
    issues = analyze_snippet(engine, code)
    assert len(issues) == 0


# =============================================================================
# Phase 7: Container Escapes
# =============================================================================

def test_container_escape_append_is_unknown(engine):
    code = """
def collect():
    bag = []
    f = open("item.txt", "r")
    bag.append(f)
"""
    issues = analyze_snippet(engine, code)
    assert len(issues) == 1
    issue = issues[0]
    assert issue.classification == "UNKNOWN"
    assert issue.ownership_status == "CONTAINER"


def test_container_escape_extend_is_unknown(engine):
    code = """
def collect_extend():
    bag = []
    f = open("item.txt", "r")
    bag.extend([f])
"""
    issues = analyze_snippet(engine, code)
    assert len(issues) == 1
    issue = issues[0]
    assert issue.classification == "UNKNOWN"
    assert issue.ownership_status == "CONTAINER"


# =============================================================================
# Phase 8: Policy & CLI Integration
# =============================================================================

def test_policy_default_does_not_block_unknown():
    policy = SecurityPolicy(block_level="HIGH", block_unknown=False)
    issue = LeakIssue(
        rule_id="RULE001",
        message="Resource escaped",
        severity=Severity.LOW,
        location=SourceLocation("test.py", 1, 0),
        problem="Escaped",
        classification="UNKNOWN",
        ownership_status="TRANSFERRED",
    )
    assert not policy.is_issue_blocking(issue)


def test_policy_block_unknown_blocks_unknown():
    policy = SecurityPolicy(block_level="HIGH", block_unknown=True)
    issue = LeakIssue(
        rule_id="RULE001",
        message="Resource escaped",
        severity=Severity.LOW,
        location=SourceLocation("test.py", 1, 0),
        problem="Escaped",
        classification="UNKNOWN",
        ownership_status="TRANSFERRED",
    )
    assert policy.is_issue_blocking(issue)


def test_analysis_report_clean_files_ignores_unknown():
    report = AnalysisReport(target_path="dummy", block_unknown=False)
    report.files_scanned = 1
    issue = LeakIssue(
        rule_id="RULE001",
        message="Resource escaped",
        severity=Severity.LOW,
        location=SourceLocation("test.py", 1, 0),
        problem="Escaped",
        classification="UNKNOWN",
        ownership_status="TRANSFERRED",
    )
    report.issues.append(issue)
    assert report.clean_files_count == 1
    assert not report.has_errors_or_issues


def test_analysis_report_clean_files_counts_unknown_when_blocking():
    report = AnalysisReport(target_path="dummy", block_unknown=True)
    report.files_scanned = 1
    issue = LeakIssue(
        rule_id="RULE001",
        message="Resource escaped",
        severity=Severity.LOW,
        location=SourceLocation("test.py", 1, 0),
        problem="Escaped",
        classification="UNKNOWN",
        ownership_status="TRANSFERRED",
    )
    report.issues.append(issue)
    assert report.clean_files_count == 0
    assert report.has_errors_or_issues


def test_cli_scan_unknown_dir_default_exit_zero():
    ret = main(["--target", "python/unknown/"])
    assert ret == 0


def test_cli_scan_unknown_dir_block_unknown_exit_one():
    ret = main(["--target", "python/unknown/", "--block-unknown"])
    assert ret == 1


# =============================================================================
# Phase 9: Zero Code Execution Verification
# =============================================================================

def test_zero_code_execution_with_hostile_syntax(engine):
    # This snippet contains dangerous execution statements: if executed, it would raise SystemExit
    code = """
import sys
sys.exit(99)
def dangerous():
    f = open("data.txt", "r")
    f.close()
"""
    # ast.parse + analyze_tree must succeed without raising SystemExit or executing sys.exit
    issues = analyze_snippet(engine, code)
    assert len(issues) == 0
