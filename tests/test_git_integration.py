"""Tests for Git version control and GitHub workflow manager."""

import tempfile
from pathlib import Path
import pytest

from git_integration.git_manager import GitManager


def test_git_branch_name_generation():
    mgr = GitManager()
    branch = mgr.generate_branch_name("fix-resource-leaks")
    assert branch.startswith("leakguard/fix-resource-leaks-")


def test_connect_github_validation():
    mgr = GitManager()
    valid_res = mgr.connect_github("octocat/hello-world", base_branch="main")
    assert valid_res["success"] is True
    assert valid_res["repository"] == "octocat/hello-world"

    invalid_res = mgr.connect_github("invalid_format")
    assert invalid_res["success"] is False
    assert "Invalid repository format" in invalid_res["error"]


def test_commit_requires_verified_files():
    mgr = GitManager()
    with tempfile.TemporaryDirectory() as tmp_dir:
        res = mgr.create_branch_and_commit(
            workspace_path=Path(tmp_dir),
            branch_name="leakguard/test-branch",
            commit_message="test",
            verified_files=[],
        )
        assert res["success"] is False
        assert "No verified fixes are ready to commit" in res["error"]


def test_pull_request_markdown_generation():
    mgr = GitManager()
    mgr.connect_github("org/repo")
    pr_res = mgr.create_pull_request(
        branch_name="leakguard/fix-leaks-123",
        title="LeakGuard: Fix detected resource leaks",
        description="",
        verified_count=3,
        files_changed=["db.py", "service.py"],
    )
    assert pr_res["success"] is True
    assert pr_res["title"] == "LeakGuard: Fix detected resource leaks"
    assert "**Verified Fixes Applied:** 3" in pr_res["body"]
    assert "Pure AST Static Analysis passed" in pr_res["body"]
    assert pr_res["pr_url"].startswith("https://github.com/org/repo/pull/")
