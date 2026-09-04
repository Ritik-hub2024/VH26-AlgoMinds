# LeakGuard Benchmarks & Resource Lifecycle Matrix

This directory contains automated benchmark suites for validating LeakGuard:
1. **Test Corpus Benchmark (`run_benchmark.py`)**: End-to-end static validation against the 12 canonical Python test cases.
2. **Parser Micro-Benchmark (`benchmark_parser.py`)**: AST parsing throughput and performance metrics.

---

## 1. Test Corpus Benchmark

The automated benchmark evaluates LeakGuard's `AnalysisEngine` against all 12 canonical test files covering resource acquisition, release, early returns, branch divergences, exception handlers, finally cleanup, and syntax validation.

### Running the Benchmark

```bash
# Direct execution
python benchmark/run_benchmark.py

# Or via the runner
python run.py benchmark
```

Outputs machine-readable metrics to `benchmark/results.json` and renders an actionable terminal summary table.

---

## 2. Resource Lifecycle Matrix

Below is the verified matrix generated from actual execution of the canonical test corpus:

| Test Case File | Category | Resource Type | Expected | Actual Result | Status | Verified Behavior / Leak Path |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `python/leaks/file_no_close.py` | Leak | File | **LEAK** | **LEAK** | **PASS** | `L4: open() -> L6: return (leak)` |
| `python/leaks/early_return.py` | Leak | File | **LEAK** | **LEAK** | **PASS** | `L4: open() -> L5: if skip -> L6: return (leak)` |
| `python/leaks/exception_leak.py` | Leak | File | **LEAK** | **LEAK** | **PASS** | `L5: open() -> L6: try -> L8: except Exception -> L9: return (leak)` |
| `python/leaks/raise_leak.py` | Leak | File | **LEAK** | **LEAK** | **PASS** | `L5: open() -> L6: raise (leak)` |
| `python/leaks/sqlite_leak.py` | Leak | SQLite connection | **LEAK** | **LEAK** | **PASS** | `L5: sqlite3.connect() -> L8: return (leak)` |
| `python/leaks/sqlite_early_return.py` | Leak | SQLite connection | **LEAK** | **LEAK** | **PASS** | `L5: sqlite3.connect() -> L6: if flag -> L7: return (leak)` |
| `python/safe/explicit_close.py` | Safe | File | **SAFE** | **SAFE** | **PASS** | Guaranteed closed via `f.close()` at line 6 |
| `python/safe/with_file.py` | Safe | File | **SAFE** | **SAFE** | **PASS** | Safely managed by context manager (`with open`) |
| `python/safe/finally_close.py` | Safe | File | **SAFE** | **SAFE** | **PASS** | Guaranteed closed in `finally:` block at line 8 |
| `python/safe/exception_finally.py` | Safe | File | **SAFE** | **SAFE** | **PASS** | Guaranteed closed in `finally:` block at line 10 |
| `python/safe/sqlite_safe.py` | Safe | SQLite connection | **SAFE** | **SAFE** | **PASS** | Guaranteed closed in `finally:` block at line 11 |
| `python/syntax/invalid_python.py` | Syntax | N/A | **SYNTAX_ERROR** | **SYNTAX_ERROR** | **PASS** | `SyntaxError` caught and reported cleanly by AST parser |

---

## 3. Quality Metrics & Confusion Matrix

Observed performance metrics on the 12 canonical test cases:

| Metric | Formula | Observed Value | Description |
| :--- | :--- | :--- | :--- |
| **Total Test Cases** | $N$ | **12** | Complete canonical suite |
| **True Positives (TP)** | — | **6** | Expected leaks correctly identified |
| **True Negatives (TN)** | — | **5** | Safe patterns correctly identified |
| **False Positives (FP)** | — | **0** | Spurious leak warnings on safe code |
| **False Negatives (FN)** | — | **0** | Undetected real resource leaks |
| **Syntax Errors (TP)** | — | **1** | Syntax errors correctly captured |
| **Precision** | $\frac{\text{TP}}{\text{TP} + \text{FP}}$ | **100.0%** ($1.0$) | Reported leaks that are genuine |
| **Recall** | $\frac{\text{TP}}{\text{TP} + \text{FN}}$ | **100.0%** ($1.0$) | Actual leaks successfully flagged |
| **F1 Score** | $2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$ | **100.0%** ($1.0$) | Harmonic mean of precision & recall |
| **Accuracy** | $\frac{\text{TP} + \text{TN}}{\text{TP} + \text{TN} + \text{FP} + \text{FN}}$ | **100.0%** ($1.0$) | Overall classification accuracy |

> [!NOTE]
> **Corpus Scope Disclaimer**: This benchmark is self-created for the MVP hackathon corpus. Metrics reflect performance on the 12 included canonical test files under intra-procedural scope. Cross-function ownership is an explicit limitation.

---

## 4. Parser Throughput Micro-Benchmark

Measures pure AST parsing speed across all valid Python files in any directory:

```bash
python benchmark/benchmark_parser.py .
```

Reports elapsed time (ms), throughput in files/sec, lines/sec, and KB/sec.
