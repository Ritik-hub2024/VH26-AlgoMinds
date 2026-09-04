"""LeakGuard - Pure AST Python Static Analyzer for Detecting Resource and Memory Leaks."""

import sys
from pathlib import Path

# Ensure the root directory containing parser, analyzer, models, reporter is in sys.path
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from models import SourceLocation, Severity, LeakIssue, Resource, SyntaxErrorInfo, ParseResult, AnalysisReport
from parser import ASTParser, parse_python_file, parse_python_source
from analyzer import BaseRule, AnalysisEngine
from reporter import ConsoleReporter, JSONReporter

__version__ = "0.1.0"

__all__ = [
    "SourceLocation",
    "Severity",
    "LeakIssue",
    "Resource",
    "SyntaxErrorInfo",
    "ParseResult",
    "AnalysisReport",
    "ASTParser",
    "parse_python_file",
    "parse_python_source",
    "BaseRule",
    "AnalysisEngine",
    "ConsoleReporter",
    "JSONReporter",
]
