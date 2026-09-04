# LeakGuard

> Pure AST-based Python Static Analyzer for Detecting Resource and Memory Leaks

LeakGuard is a lightweight, zero-dependency static analysis tool designed specifically for Python codebases. It inspects Python Abstract Syntax Trees (AST) to identify resource leaks (unclosed files, dangling SQLite connections) and syntax anomalies safely, without executing any target code or relying on fragile regex patterns.

---

## Core Design Principles

1. **Zero Code Execution**: Code is parsed strictly using Python's built-in `ast.parse`. Target files are never executed, imported, or dynamically evaluated.
2. **Pure AST Analysis**: Leak detection rules rely strictly on AST node visitor structures (`ast.NodeVisitor`) and control-flow evaluation. No regular expressions or text-matching heuristics.
3. **Extensible Rule Architecture**: Shared control-flow evaluation engine (`BaseResourceLifecycleRule`) abstracts acquisition and release semantics, making adding new resource types straightforward.
4. **Actionable Reporting**: Reports provide the 6 critical dimensions needed for immediate resolution: **File**, **Line**, **Resource**, **Problem**, **Leak Path**, and **Recommendation**.
5. **Context Manager Recognition**: Native understanding that `with open(...) as f:` and `with contextlib.closing(...) as conn:` guarantee cleanup (`__exit__`) across all control paths.

---

## Supported Resource Types

LeakGuard features an extensible rule-based lifecycle analysis system supporting multiple resource categories:

| Resource Type | Acquisition Pattern | Release Pattern | Rule ID | Scope |
| :--- | :--- | :--- | :--- | :--- |
| **File Resources** | `open(...)`, `builtins.open(...)`, `io.open(...)` | `f.close()` or `with open(...) as f:` | `LEAK001` | Sequential, branch, early-return, try/finally |
| **SQLite Connections** | `sqlite3.connect(...)`, `connect(...)` | `conn.close()` in `finally:` or `with closing(...)` | `LEAK002` | Sequential, branch, early-return, exception paths, try/finally |

### Extensible Rule Architecture

All resource lifecycle rules derive from `BaseResourceLifecycleRule`:
- **Shared Control-Flow Engine**: Automatically inspects sequential flows, if/else branch divergence, early returns, unhandled exception paths, and guaranteed `finally:` cleanup blocks.
- **Pluggable Rules**: Adding a new resource type (e.g., sockets, threads, custom connection pools) requires only subclassing `BaseResourceLifecycleRule` and defining acquisition and release predicates.

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
 Target:   python/leaks/database_leak.py
 Files:    1 scanned
 Duration: 0.0040s
----------------------------------------------------------------

Detected Issues (1):
  [1] [HIGH] LEAK002 in get_users()
      File:           python/leaks/database_leak.py
      Line:           5
      Resource:       conn (type: SQLite connection)
      Problem:        Early return at line 8 exits before 'conn.close()' is reached.
      Leak Path:      L5: sqlite3.connect() -> L8: return (leak)
      Recommendation: Call 'conn.close()' before returning at line 8, or wrap in try...finally.

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
│       ├── base_lifecycle.py # Reusable AST control-flow lifecycle engine
│       ├── file_leak.py   # LEAK001: File resource leak rule
│       └── sqlite_leak.py # LEAK002: SQLite connection leak rule
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
├── python/                # Canonical test case suite
│   ├── leaks/             # Leak cases (file & SQLite)
│   │   ├── database_leak.py         # Unclosed sqlite3.connect()
│   │   ├── database_early_return.py # sqlite3.connect() with early return
│   │   ├── early_return.py          # open() with early return
│   │   ├── exception_leak.py        # Exception path unclosed
│   │   ├── file_no_close.py         # Raw unclosed file
│   │   └── raise_leak.py            # Unclosed exit via raise
│   └── safe/              # Verified safe patterns
│       ├── database_safe.py         # Guaranteed closed in finally
│       ├── exception_finally.py     # Exception handler with finally close
│       ├── explicit_close.py        # Sequential explicit close()
│       ├── finally_close.py         # Guaranteed closed in finally block
│       └── with_file.py             # Context manager with open()
│
├── frontend/              # Web security dashboard
│   ├── index.html
│   ├── style.css
│   └── app.js
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
└── tests/                 # Comprehensive test suite (89 passing tests)
    ├── __init__.py
    ├── test_parser.py     # AST parser & syntax error tests
    ├── test_cli.py        # CLI discovery & scanning tests
    ├── test_models.py     # Data model tests
    ├── test_detector.py   # Control-flow & leak detector tests
    ├── test_analyzer.py   # Resource lifecycle & exception tests
    ├── test_sqlite_leak.py# SQLite connection leak & finally tests
    ├── test_reporter.py   # Reporter formatting tests
    └── test_server.py     # Local server & API tests
```

---

## Quick Start

### 1. Scan a File or Directory
Run the CLI on any Python file or folder:
```bash
# Scan a single file (e.g. SQLite database leak)
python cli.py python/leaks/database_leak.py

# Scan a directory
python cli.py python/

# Output machine-readable JSON
python cli.py python/ --format json
```

### 2. Run Tests
Ensure all tests pass using `pytest`:
```bash
# Run root test suite (75 tests)
python -m pytest tests/ -v

# Run backend test suite (14 tests)
python -m pytest backend/tests/ -v
```

### 3. Run the Web Dashboard
Launch the interactive security dashboard with live Python AST scanning:
```bash
# Start the local server
python app.py
```
Open `http://localhost:8000` to interact with the dashboard:
- Select a target (e.g. `Examples Suite (examples/)`, `python/leaks/`, or `python/safe/`)
- Click **Scan Python Project** to execute live AST control-flow analysis
- Inspect PASS / FAILED status, leak paths, and actionable recommendations
- Click **Reset** to restore the dashboard to its clean state

---

## Scope & Analysis Boundaries

> [!IMPORTANT]
> **Intra-Procedural Scope**: LeakGuard performs intra-procedural AST control-flow analysis within function definitions and statement blocks.
>
> **Explicit Boundary**: Cross-function resource ownership (e.g. creating an open file handle or SQLite connection inside a factory function or passing it to an asynchronous worker across module boundaries) is an active research area for inter-procedural static analysis and is **explicitly not claimed to be solved** in this version.

---

## License

MIT
