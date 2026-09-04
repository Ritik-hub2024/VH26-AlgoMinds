# LeakGuard

> Pure AST-based Python Static Analyzer for Detecting Resource and Memory Leaks

LeakGuard is a lightweight, zero-dependency static analysis tool designed specifically for Python codebases. It inspects Python Abstract Syntax Trees (AST) to identify potential resource leaks (unclosed files, dangling sockets, unmanaged database connections) and syntax anomalies safely, without executing any target code.

---

## Core Design Principles

1. **Zero Code Execution**: Code is parsed strictly using Python's built-in `ast.parse`. Target files are never executed, imported, or dynamically evaluated.
2. **Pure AST Analysis**: Leak detection rules rely strictly on AST node visitor structures (`ast.NodeVisitor`). No brittle regular expressions or text-matching heuristics.
3. **Zero Heavy Dependencies**: The core analyzer, models, parser, reporter, and CLI rely exclusively on Python standard library modules (`ast`, `argparse`, `dataclasses`, `pathlib`, `json`).
4. **Resilient Syntax Error Handling**: Gracefully intercepts `SyntaxError` and file decode issues with line numbers, column offsets, and error contexts.

---

## Repository Structure

```
LeakGuard/
├── .gitignore             # Standard Python ignore patterns
├── README.md              # Project documentation
├── pyproject.toml         # Packaging and build specifications
├── requirements.txt       # Project dependencies (pytest for tests)
├── cli.py                 # Direct CLI entry point
│
├── parser/                # AST parsing and syntax validation
│   ├── __init__.py
│   └── ast_parser.py      # Safe AST parser implementation
│
├── analyzer/              # Core analysis abstractions
│   ├── __init__.py
│   ├── base.py            # BaseRule AST NodeVisitor contract
│   └── engine.py          # AnalysisEngine orchestration
│
├── models/                # Typed domain models
│   ├── __init__.py
│   ├── location.py        # SourceLocation dataclass
│   ├── issue.py           # LeakIssue and Severity dataclasses
│   └── report.py          # ParseResult and AnalysisReport
│
├── reporter/              # Output formatters
│   ├── __init__.py
│   ├── console.py         # Formatted terminal output
│   └── json_reporter.py   # Machine-readable JSON output
│
├── leakguard/             # Top-level package namespace
│   ├── __init__.py
│   └── cli.py             # Package CLI entrypoint
│
├── frontend/              # Minimal dashboard frontend
│   ├── index.html         # Lightweight dashboard UI
│   ├── style.css          # Modern dark-mode styling
│   └── app.js             # Interactive results explorer
│
├── examples/              # Demonstration sample scripts
│   ├── valid_sample.py    # Clean Python code with context manager
│   ├── invalid_syntax_sample.py # Intentional syntax error sample
│   └── resource_sample.py # Resource leak demonstration
│
├── benchmark/             # AST parsing throughput benchmarks
│   ├── README.md
│   └── benchmark_parser.py
│
└── tests/                 # Comprehensive test suite
    ├── __init__.py
    ├── test_parser.py     # AST parser & syntax error tests
    ├── test_cli.py        # CLI discovery & scanning tests
    ├── test_models.py     # Data model tests
    └── test_reporter.py   # Reporter formatting tests
```

---

## Quick Start

### 1. Scan a File or Directory
Run the CLI on any Python file or folder:
```bash
# Scan a single file
python cli.py examples/valid_sample.py

# Scan a directory
python cli.py examples/

# Output machine-readable JSON
python cli.py examples/ --format json
```

### 2. Run Tests
Ensure all tests pass using `pytest` or Python's built-in `unittest`:
```bash
# Run with pytest
python -m pytest tests/ -v

# Or run with standard library unittest (zero extra packages)
python -m unittest discover -s tests -v
```

### 3. Run Parser Benchmark
Measure parsing throughput across any directory:
```bash
python benchmark/benchmark_parser.py examples/
```

---

## MVP Foundation Status

- [x] Pure AST parser using `ast.parse`
- [x] Detailed `SyntaxError` reporting with line, column offset, and error text
- [x] Zero code execution guarantee
- [x] CLI entry point supporting both single files and recursive directory traversal
- [x] Output reporters for terminal console and structured JSON
- [x] Typed domain models (`SourceLocation`, `LeakIssue`, `ParseResult`, `AnalysisReport`)
- [x] AST visitor base rule framework (`BaseRule`, `AnalysisEngine`)
- [x] Test suite with 100% test pass rate
- [x] Benchmarking utility for parser throughput
- [x] Minimal dashboard frontend structure

---

## License

MIT
