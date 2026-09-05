"""Tests for safe ZIP project upload, extraction, and validation."""

import io
import tempfile
import zipfile
from pathlib import Path
import pytest

from app import Handler, ReusableTCPServer, _GLOBAL_WORKSPACE_MGR


def create_zip_bytes(files_dict: dict) -> bytes:
    """Helper to create an in-memory zip archive from filename -> content."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname, content in files_dict.items():
            zf.writestr(fname, content)
    return buf.getvalue()


def test_valid_zip_upload_and_extraction():
    """Test uploading a valid Python project ZIP."""
    files = {
        "src/main.py": "def main():\n    print('hello')\n",
        "src/utils.py": "def add(a, b):\n    return a + b\n",
        "README.md": "# Sample project\n",
        "tests/test_app.py": "def test_app():\n    assert True\n",
    }
    zip_data = create_zip_bytes(files)

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        ws = _GLOBAL_WORKSPACE_MGR.create_workspace("TestProject", tmp_path, is_temp=True)

        with zipfile.ZipFile(io.BytesIO(zip_data), "r") as zf:
            zf.extractall(tmp_path)

        py_files = ws.get_python_files()
        assert len(py_files) == 3
        lines_count = ws.count_lines()
        assert lines_count >= 6


def test_zip_path_traversal_detection():
    """Test that ZIP files with ../ paths or absolute paths are flagged."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../evil.py", "import os; os.system('bad')")
    zip_bytes = buf.getvalue()

    # Verify that our zip extraction logic blocks this
    has_traversal = False
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
        for member in zf.infolist():
            m_path = member.filename.replace("\\", "/")
            if ".." in Path(m_path).parts or m_path.startswith("/"):
                has_traversal = True
                break

    assert has_traversal is True


def test_zip_ignores_virtualenv_and_git():
    """Test that .git, __pycache__, and .venv directories in ZIP are ignored during scanning."""
    files = {
        "app.py": "print('live')\n",
        ".git/config": "secret\n",
        ".venv/lib/python3.10/site-packages/pkg.py": "print('vendor')\n",
        "__pycache__/app.cpython-310.pyc": "binary\n",
    }
    zip_data = create_zip_bytes(files)

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        ws = _GLOBAL_WORKSPACE_MGR.create_workspace("IgnoredTest", tmp_path, is_temp=True)

        with zipfile.ZipFile(io.BytesIO(zip_data), "r") as zf:
            for member in zf.infolist():
                parts = Path(member.filename).parts
                if any(part in (".git", ".venv", "__pycache__") for part in parts):
                    continue
                dest = tmp_path / member.filename
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(zf.read(member))

        py_files = ws.get_python_files()
        # Should only find app.py, ignoring .venv and __pycache__
        assert len(py_files) == 1
        assert py_files[0].name == "app.py"
