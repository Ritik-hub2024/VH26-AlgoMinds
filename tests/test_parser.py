"""Comprehensive tests for ASTParser syntax validation and error handling."""

import unittest
from pathlib import Path
import tempfile
from parser.ast_parser import ASTParser, parse_python_file, parse_python_source


class TestASTParser(unittest.TestCase):
    """Tests for ASTParser adhering to zero-execution and pure AST parsing."""

    def test_parse_valid_code(self):
        parser = ASTParser()
        res = parser.parse_source("x = 42\nprint(x)")
        self.assertTrue(res.success)
        self.assertIsNotNone(res.tree)
        self.assertIsNone(res.syntax_error)
        self.assertIsNone(res.read_error)

    def test_parse_syntax_error(self):
        parser = ASTParser()
        res = parser.parse_source("def broken(\n")
        self.assertFalse(res.success)
        self.assertIsNone(res.tree)
        self.assertIsNotNone(res.syntax_error)
        self.assertIsNotNone(res.syntax_error.line)

    def test_parse_syntax_error_details(self):
        parser = ASTParser()
        code = "def foo():\n    return 1 +\n"
        res = parser.parse_source(code, filename="bad_math.py")
        self.assertFalse(res.success)
        self.assertIsNotNone(res.syntax_error)
        self.assertEqual(res.syntax_error.filename, "bad_math.py")
        self.assertEqual(res.syntax_error.line, 2)
        self.assertIsNotNone(res.syntax_error.column)
        self.assertIn("bad_math.py", str(res.syntax_error))

    def test_parse_modern_python_features(self):
        """Verify modern Python syntax constructs parse cleanly into AST."""
        code = """
async def fetch(url: str) -> dict[str, int]:
    match url:
        case "http" | "https":
            return {"status": 200}
        case _:
            if (n := len(url)) > 0:
                return {"status": n}
            return {"status": 400}
"""
        res = parse_python_source(code)
        self.assertTrue(res.success)
        self.assertIsNotNone(res.tree)

    def test_parse_empty_source(self):
        res = parse_python_source("")
        self.assertTrue(res.success)
        self.assertIsNotNone(res.tree)

    def test_parse_whitespace_and_comments(self):
        code = "# Just comments\n\n   # Another comment\n"
        res = parse_python_source(code)
        self.assertTrue(res.success)
        self.assertIsNotNone(res.tree)

    def test_parse_nonexistent_file(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            missing = Path(tmp_dir) / "does_not_exist.py"
            res = parse_python_file(missing)
            self.assertFalse(res.success)
            self.assertIsNotNone(res.read_error)
            self.assertIn("not found", res.read_error.lower())

    def test_zero_code_execution_guarantee(self):
        """Verify that parsing does not execute side effects."""
        flag = {"executed": False}

        malicious_code = """
raise RuntimeError("Code was executed!")
"""
        parser = ASTParser()
        res = parser.parse_source(malicious_code, filename="unexecuted.py")
        self.assertTrue(res.success)
        self.assertIsNotNone(res.tree)
        self.assertFalse(flag["executed"])


if __name__ == "__main__":
    unittest.main()
