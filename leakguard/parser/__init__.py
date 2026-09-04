"""Expose parser in leakguard namespace."""

from parser import ASTParser, parse_python_file, parse_python_source

__all__ = ["ASTParser", "parse_python_file", "parse_python_source"]
