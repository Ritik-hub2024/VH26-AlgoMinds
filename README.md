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

## Round-2 Validation & Benchmark Suite

### 1. Supported Python Resources
LeakGuard supports Python as its **only** target language. The analyzer provides lifecycle rules for:
- **File Resources (`LEAK001`)**: Objects opened via built-in `open()`, `builtins.open()`, or `io.open()`, released via `f.close()` or `with open(...) as f:`.
- **SQLite Database Connections (`LEAK002`)**: Connection objects acquired via `sqlite3.connect()` or `connect()`, released via `conn.close()` in `finally:` or `with contextlib.closing(...) as conn:`.

### 2. Detection Scenarios
The intra-procedural AST control-flow engine analyzes:
- **Sequential Flows**: Resource acquisition followed by exit or scope termination without explicit release.
- **Early-Return Divergence**: `if` / `else` branches where one path returns or breaks before release is reached.
- **Exception Paths**: `try` blocks where an `except` handler exits via `return` or `raise` without cleanup.
- **Guaranteed `finally:` Cleanup**: Recognition that calls inside `finally:` blocks run unconditionally on all paths.
- **Context Managers**: Recognition that `with` statements guarantee deterministic cleanup via `__exit__`.
- **Syntax Error Isolation**: Non-compilable Python files are trapped gracefully with accurate line/column metadata without crashing the analyzer.

### 3. Canonical Python Test Corpus (12 Cases)
The project includes a 12-file canonical test corpus under `python/`:

```
python/
├── leaks/                         # 6 Intentional Leak Cases
│   ├── file_no_close.py           # Unclosed file handle in sequential code
│   ├── early_return.py            # File open with early return in if branch
│   ├── exception_leak.py          # File open with unclosed return in except
│   ├── raise_leak.py              # File open with unhandled raise before close
│   ├── sqlite_leak.py             # sqlite3.connect() unclosed in sequential code
│   └── sqlite_early_return.py     # sqlite3.connect() with early return in if
│
├── safe/                          # 5 Verified Safe Patterns
│   ├── explicit_close.py          # Sequential f.close() guaranteed
│   ├── with_file.py               # Context manager with open(...) as f:
│   ├── finally_close.py           # Guaranteed f.close() in finally:
│   ├── exception_finally.py       # try / except with f.close() in finally:
│   └── sqlite_safe.py             # Guaranteed conn.close() in finally:
│
└── syntax/                        # 1 Syntax Error Case
    └── invalid_python.py          # Intentional syntax error for AST parser validation
```

### 4. Benchmark Method
Execute the automated benchmark against the full test corpus:
```bash
python benchmark/run_benchmark.py
# or via runner
python run.py benchmark
```

The benchmark runs `AnalysisEngine` against all 12 test cases, compares actual findings against expected outcomes, calculates quality metrics, outputs a formatted terminal matrix, and writes machine-readable results to `benchmark/results.json`.

### 5. Observed FP / FN Results (Quality Metrics)
Evaluated on the 12 canonical test corpus cases:

| Metric | Observed Value | Description |
| :--- | :--- | :--- |
| **Total Test Cases** | **12** | 6 leaks, 5 safe, 1 syntax error |
| **True Positives (TP)** | **6** | All 6 intentional leaks correctly flagged |
| **True Negatives (TN)** | **5** | All 5 safe patterns verified with zero alerts |
| **False Positives (FP)** | **0** | Zero spurious alerts on safe code |
| **False Negatives (FN)** | **0** | Zero missed leaks |
| **Syntax Errors (TP)** | **1** | Syntax error caught and reported cleanly |
| **Precision** | **100.0%** ($1.0$) | Fraction of detected leaks that are genuine |
| **Recall** | **100.0%** ($1.0$) | Fraction of real leaks detected |
| **F1 Score** | **100.0%** ($1.0$) | Harmonic mean of precision and recall |
| **Accuracy** | **100.0%** ($1.0$) | Overall classification accuracy |

> [!NOTE]
> **Corpus Benchmark Disclaimer**: This benchmark is self-created for the MVP hackathon corpus. Metrics reflect performance on the 12 included canonical test files under intra-procedural scope.

### 6. Known Limitations
- **Intra-Procedural Scope**: Analysis occurs within function and module statement blocks.
- **Cross-Function Resource Ownership**: Resources allocated in factory functions, yielded from generators, or passed across inter-procedural boundaries are an active research frontier and are **explicitly not claimed to be solved** in this MVP.
- **Dynamic Connection Pools**: ORM-managed connections (e.g. SQLAlchemy sessions, Django ORM connection pooling) operate via complex runtime wrappers and are outside the scope of raw `sqlite3.connect()` AST detection.

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
 Target:   python/leaks/sqlite_leak.py
 Files:    1 scanned
 Duration: 0.0040s
----------------------------------------------------------------

Detected Issues (1):
  [1] [HIGH] LEAK002 in get_users()
      File:           python/leaks/sqlite_leak.py
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
├── run.py                 # Multi-command runner (demo, test, scan, benchmark, app)
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
│   ├── leaks/             # 6 intentional leak cases
│   │   ├── early_return.py          # open() with early return
│   │   ├── exception_leak.py        # Exception path unclosed
│   │   ├── file_no_close.py         # Raw unclosed file
│   │   ├── raise_leak.py            # Unclosed exit via raise
│   │   ├── sqlite_early_return.py   # sqlite3.connect() with early return
│   │   └── sqlite_leak.py           # Unclosed sqlite3.connect()
│   ├── safe/              # 5 verified safe patterns
│   │   ├── exception_finally.py     # Exception handler with finally close
│   │   ├── explicit_close.py        # Sequential explicit close()
│   │   ├── finally_close.py         # Guaranteed closed in finally block
│   │   ├── sqlite_safe.py           # Guaranteed sqlite close in finally
│   │   └── with_file.py             # Context manager with open()
│   └── syntax/            # 1 syntax error case
│       └── invalid_python.py        # Intentional syntax error
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
├── benchmark/             # Automated benchmark suite & results
│   ├── README.md          # Benchmark guide & Resource Lifecycle Matrix
│   ├── results.json       # Generated machine-readable benchmark metrics
│   ├── run_benchmark.py   # Automated corpus benchmark runner
│   └── benchmark_parser.py# AST parsing throughput micro-benchmark
│
└── tests/                 # Comprehensive test suite (103 passing tests)
    ├── __init__.py
    ├── test_parser.py     # AST parser & syntax error tests
    ├── test_cli.py        # CLI discovery & scanning tests
    ├── test_models.py     # Data model tests
    ├── test_detector.py   # Control-flow & leak detector tests
    ├── test_analyzer.py   # Canonical corpus & exception tests
    ├── test_sqlite_leak.py# SQLite connection leak & finally tests
    ├── test_reporter.py   # Reporter formatting tests
    └── test_server.py     # Local server & API tests
```

---

## Quick Start

### 1. Scan a File or Directory
Run the CLI on any Python file or folder:
```bash
# Scan a directory
python cli.py python/leaks/

# Scan the safe suite
python cli.py python/safe/

# Output machine-readable JSON
python cli.py python/ --format json
```

### 2. Run Tests
Ensure all tests pass using `pytest`:
```bash
# Run root test suite (89 tests)
python -m pytest tests/ -v

# Run backend test suite (14 tests)
python -m pytest backend/tests/ -v
```

### 3. Run Benchmark
Run the automated benchmark on the 12-file canonical corpus:
```bash
python benchmark/run_benchmark.py
```

### 4. Run the Web Dashboard
Launch the interactive security dashboard with live Python AST scanning:
```bash
python app.py
```
Open `http://localhost:8000` to interact with the dashboard:
- Select a target (`Entire Test Suite (python/)`, `Leaks Suite (python/leaks/)`, `Safe Suite (python/safe/)`, `Syntax Suite (python/syntax/)`)
- Click **Scan Python Project** to execute live AST control-flow analysis
- Inspect PASS / FAILED status, leak paths, and actionable recommendations
- Click **Reset** to restore the dashboard to its clean state

---

## CI/CD Integration

LeakGuard integrates directly into GitHub Actions and CI/CD pipelines to block resource leaks before code merges into production.

### How the CI Pipeline Works
1. **Developer pushes code** or opens a pull request.
2. **GitHub Actions workflow triggers** (`.github/workflows/ci.yml`) across supported Python versions (3.10, 3.11, 3.12, 3.13).
3. **Environment setup & tests**: Dependencies are installed in a clean virtual environment and the full test suite runs (`pytest -v`).
4. **LeakGuard scans Python code**:
   ```bash
   python cli.py --target python/safe/ --github-summary
   ```
5. **Deterministic Exit Codes**:
   - `Safe code  -> exit 0 -> CI PASS`
   - `Leak found -> exit 1 -> CI FAIL`
6. **Developer feedback**: An actionable markdown report is automatically posted to the GitHub Actions Job Summary with exact file locations, leak paths, and fix recommendations.
7. **Developer resolves the leak** and pushes again until the pipeline turns green.

### Exit Code Semantics
```
Safe code   → exit 0 → CI PASS
Leak found  → exit 1 → CI FAIL
Syntax error→ exit 1 → CI FAIL
```

---

## License

MIT
