# LeakGuard

> Pure AST-based Python Static Analyzer for Detecting Resource and Memory Leaks

LeakGuard is a lightweight, zero-dependency static analysis tool designed specifically for Python codebases. It inspects Python Abstract Syntax Trees (AST) to identify resource leaks (unclosed files, dangling handles) and syntax anomalies safely, without executing any target code or relying on fragile regex patterns.

---

## Core Design Principles

1. **Zero Code Execution**: Code is parsed strictly using Python's built-in `ast.parse`. Target files are never executed, imported, or dynamically evaluated.
2. **Pure AST Analysis**: Leak detection rules rely strictly on AST node visitor structures (`ast.NodeVisitor`) and control-flow evaluation. No regular expressions or text-matching heuristics.
3. **Zero Heavy Dependencies**: The core analyzer, models, parser, reporter, and CLI rely exclusively on Python standard library modules (`ast`, `argparse`, `dataclasses`, `pathlib`, `json`).
4. **Actionable Reporting**: Reports provide the 6 critical dimensions needed for immediate resolution: **File**, **Line**, **Resource**, **Problem**, **Leak Path**, and **Recommendation**.
5. **Context Manager Recognition**: Native understanding that `with open(...) as f:` guarantees resource cleanup (`__exit__`) even across early returns.

---

## 2-Minute Jury Demo

Run the automated live jury demo:
```bash
python demo.py
# or
python run.py demo
```

The demo executes the complete flow:
1. **SAFE**: Scan clean baseline (`safe_file.py`).
2. **INTRODUCE LEAK**: Introduce an early return inside an `if` branch (`open -> if condition -> return -> close`).
3. **LEAK DETECTED**: Scan leaking code and produce an actionable CLI report with exact leak path.
4. **FIX & VERIFY**: Refactor with `with open(...) as f:` and verify clean status.
5. **BOUNDARY**: Discuss intra-procedural scope vs cross-function ownership.

See [DEMO.md](DEMO.md) for full presentation notes and timings.

---

## Actionable Report Format

When LeakGuard detects an unclosed resource leak, it formats all actionable dimensions clearly:

```text
================================================================
  LeakGuard Static Analysis Report (Jury Version)
  Scope: Intra-procedural AST Control-Flow Analysis
================================================================
 Target:   python/leak_early_return.py
 Files:    1 scanned
 Duration: 0.0029s
----------------------------------------------------------------

Detected Issues (1):
  [1] [HIGH] LEAK001 in parse_header_or_skip()
      File:           python/leak_early_return.py
      Line:           10
      Resource:       f (type: file)
      Problem:        Resource 'f' opened at line 10 is not closed if condition 'skip' at line 12 is met due to early return at line 14.
      Leak Path:      L10: open() -> L12: if skip -> L14: return (leak)
      Recommendation: Use 'with open(...) as f:', or invoke 'f.close()' before returning at line 14.

----------------------------------------------------------------
 Result: FAILED: Resource leaks or syntax errors detected.
 Summary: 0/1 clean files, 0 syntax errors, 1 issues.
 Note:   Intra-procedural scope. Cross-function ownership is not claimed.
================================================================
```

---

## Repository Structure

```
LeakGuard/
├── .gitignore             # Standard Python ignore patterns
├── README.md              # Project documentation
├── DEMO.md                # 2-minute jury demo presentation guide
├── pyproject.toml         # Packaging and build specifications
├── requirements.txt       # Project dependencies (pytest for tests)
├── cli.py                 # Direct CLI entry point
├── demo.py                # Automated 2-minute jury demo
├── run.py                 # Multi-command runner (demo, test, scan, app)
│
├── parser/                # AST parsing and syntax validation
│   ├── __init__.py
│   └── ast_parser.py      # Safe AST parser implementation
│
├── analyzer/              # Core analysis abstractions
│   ├── __init__.py
│   ├── base.py            # BaseRule AST NodeVisitor contract
│   ├── engine.py          # AnalysisEngine orchestration
│   └── rules/
│       ├── __init__.py
│       └── file_leak.py   # Control-flow file leak detector
│
├── models/                # Typed domain models
│   ├── __init__.py
│   ├── location.py        # SourceLocation dataclass
│   ├── issue.py           # LeakIssue and Severity dataclasses
│   ├── resource.py        # Resource tracking dataclass
│   └── report.py          # ParseResult and AnalysisReport
│
├── reporter/              # Output formatters
│   ├── __init__.py
│   ├── console.py         # Actionable terminal reporter
│   └── json_reporter.py   # Machine-readable JSON output
│
├── leakguard/             # Top-level package namespace
│   ├── __init__.py
│   └── cli.py             # Package CLI entrypoint
│
├── python/                # Canonical test case suite
│   ├── safe_file.py       # Sequential open -> close
│   ├── safe_try_finally.py# try / finally guarantee
│   ├── safe_with.py       # Context manager (with open)
│   ├── safe_with_early_return.py # Context manager with early return
│   ├── leak_file.py       # Unclosed handle (never closed)
│   ├── leak_early_return.py # open -> if -> return -> close
│   └── leak_if_else.py    # Asymmetrical branch leak
│
├── examples/              # Additional demonstration samples
│   ├── valid_sample.py
│   ├── invalid_syntax_sample.py
│   └── resource_sample.py
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
    ├── test_detector.py   # Control-flow & leak detector tests
    └── test_reporter.py   # Reporter formatting tests
```

---

## Quick Start

### 1. Scan a File or Directory
Run the CLI on any Python file or folder:
```bash
# Scan a single file
python cli.py python/safe_file.py

# Scan a directory
python cli.py python/

# Output machine-readable JSON
python cli.py python/ --format json
```

### 2. Run Tests
Ensure all tests pass using `pytest` or Python's built-in `unittest`:
```bash
# Run with pytest (34 tests)
python -m pytest tests/ -v

# Or run with standard library unittest (zero extra packages)
python -m unittest discover -s tests -v
```

### 3. Run Parser Benchmark
Measure parsing throughput across any directory:
```bash
python benchmark/benchmark_parser.py .
```

---

## Scope & Analysis Boundaries

> [!IMPORTANT]
> **Intra-Procedural Scope**: LeakGuard performs intra-procedural AST control-flow analysis within function definitions and statement blocks.
>
> **Explicit Boundary**: Cross-function resource ownership (e.g. creating an open file handle inside a factory function or passing it to an asynchronous worker across module boundaries) is an active research area for inter-procedural static analysis and is **explicitly not claimed to be solved** in this version.

---

## License

MIT
