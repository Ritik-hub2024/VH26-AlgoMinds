# LeakGuard Benchmark Evaluation & Accuracy Hardening Report

**Corpus Version:** Step 9 / Step 10 Canonical Benchmark  
**Total Canonical Cases:** 46  
**Execution Time:** ~0.063 seconds (~1.37 ms / file)  
**Throughput:** ~730 files / second  
**Peak Memory Overhead:** < 14 MB  

---

## 1. Executive Summary

This report documents the empirical evaluation of LeakGuard's pure Python AST static resource lifecycle analyzer. The benchmark was designed to stress-test control-flow analysis across multi-branch logic, try/except/finally blocks, loop jumps, variable reassignments, aliasing, and cross-boundary ownership transfers without executing code (`ast.parse()` only).

### Key Empirical Results

| Metric | Formula | Value | Notes |
|:---|:---:|:---:|:---|
| **Precision** | $\frac{TP}{TP + FP}$ | **100.00%** | Zero false alarms ($FP = 0$) |
| **Recall** | $\frac{TP}{TP + FN}$ | **100.00%** | All genuine leaks identified ($FN = 0$) |
| **F1 Score** | $2 \times \frac{P \times R}{P + R}$ | **1.0000** | Perfect balance on definite cases |
| **Definite Accuracy** | $\frac{TP + TN}{TP + TN + FP + FN}$ | **100.00%** | Accuracy on conclusive classifications |
| **Unknown Rate** | $\frac{UNKNOWN}{Total}$ | **21.74%** | 10 / 46 cases safely isolated |
| **Syntax Resilience** | Handled / Total | **100.00%** | 4 / 4 syntax errors isolated safely |

> [!IMPORTANT]
> **Accuracy Disclaimer**:
> These metrics apply **strictly to LeakGuard's curated 46-case canonical benchmark corpus**. They demonstrate the correctness and mathematical soundness of our intra-procedural AST algorithms on defined control-flow structures. They do **not** imply or guarantee 100% precision or recall across universal, arbitrary, or dynamically generated Python codebases.

---

## 2. Before vs. After: Step 8 Baseline to Step 9 Expansion

LeakGuard preserved its verified Step 8 baseline (`benchmark/step8_baseline_results.json`) and doubled the corpus to test complex control flows and adversarial escapes:

| Metric | Step 8 Baseline (Historical) | Step 9 Expanded (Current) | Absolute Growth | Relative Change |
|:---|:---:|:---:|:---:|:---:|
| **Total Test Cases** | 21 | **46** | +25 | +119.0% |
| **LEAK Cases** | 8 | **16** | +8 | +100.0% |
| **SAFE Cases** | 8 | **16** | +8 | +100.0% |
| **UNKNOWN Cases** | 4 | **10** | +6 | +150.0% |
| **SYNTAX Cases** | 1 | **4** | +3 | +300.0% |
| **True Positives (TP)** | 8 | **16** | +8 | +100.0% |
| **True Negatives (TN)** | 8 | **16** | +8 | +100.0% |
| **False Positives (FP)** | 0 | **0** | 0 | Maintained (0%) |
| **False Negatives (FN)** | 0 | **0** | 0 | Maintained (0%) |
| **Precision** | 100.0% | **100.0%** | 0.0% | Maintained |
| **Recall** | 100.0% | **100.0%** | 0.0% | Maintained |
| **F1 Score** | 1.0000 | **1.0000** | 0.0000 | Maintained |
| **Unknown Rate** | 19.05% | **21.74%** | +2.69% | Expected with transfers |

---

## 3. Strict Isolation of UNKNOWN Findings

A central principle of LeakGuard's architecture is **truthful static analysis**: when static analysis cannot prove that a resource is closed or leaked (e.g. passed into an unresolvable function, returned to caller, or bound to a long-lived object), it must **never guess**.

```
               Static Analysis Scope
                         |
        +----------------+----------------+
        |                                 |
   Conclusive Proof              Indeterminate Escape
        |                                 |
   +----+----+                            |
   |         |                            |
  LEAK      SAFE                       UNKNOWN
  (TP)      (TN)                  (Unknown Rate)
   |         |                            |
 Counted in Accuracy                Isolated from
 Precision & Recall               Precision & Recall
```

- **`UNKNOWN` is never counted as False Positive or False Negative**. Doing so would artificially penalize conservative analyzers for being honest about inter-procedural boundaries.
- **Default Policy**: `UNKNOWN` findings are classified as **advisory warnings** (exit code 0).
- **Strict Mode**: Teams requiring zero unverified transfers can supply `--block-unknown` to gate CI with exit code 1.

---

## 4. Full Confusion Matrix (46 Cases)

```
                            PREDICTED
                     LEAK       SAFE       UNKNOWN    SYNTAX_ERR
ACTUAL   LEAK       [ 16 ]     [  0 ]     [   0 ]    [   0   ]
         SAFE       [  0 ]     [ 16 ]     [   0 ]    [   0   ]
         UNKNOWN    [  0 ]     [  0 ]     [  10 ]    [   0   ]
         SYNTAX     [  0 ]     [  0 ]     [   0 ]    [   4   ]
```

- **Total Definite Decisions**: 32 (16 LEAK + 16 SAFE)
- **Total Indeterminate Decisions**: 10 (10 UNKNOWN)
- **Total Syntax Failures Handled**: 4 (4 SYNTAX)
- **Misclassifications**: 0

---

## 5. Complete 46-Case Corpus Manifest

### 16 LEAK Cases (True Positives)
1. `leak_basic.py`: File opened linearly, never closed.
2. `leak_early_return.py`: Early return skips trailing `f.close()`.
3. `leak_exception_unhandled.py`: Exception raised prior to `f.close()`.
4. `leak_except_return.py`: Return inside `except` handler bypasses cleanup.
5. `leak_finally_missing.py`: Try block without finally; exception causes leak.
6. `leak_sqlite_basic.py`: SQLite connection opened, never closed.
7. `leak_sqlite_early_return.py`: SQLite query branch returns early without close.
8. `leak_reassign.py`: File variable reassigned to new resource without closing first.
9. `leak_nested_branch.py`: Nested `if` branch exits without closing handle.
10. `leak_nested_try.py`: Inner try raises without finally cleanup.
11. `leak_multi_resource.py`: Two files opened (`f1`, `f2`), only `f1` closed.
12. `leak_sqlite_multi.py`: Multiple database connections, partial cleanup.
13. `leak_one_branch_close.py`: Closed in `if` branch, omitted in `else` branch.
14. `leak_loop_skip.py`: Early return inside `for` loop skips post-loop close.
15. `leak_except_return_adversarial.py`: Complex except block return skips cleanup.
16. `leak_reassign_none.py`: Variable reassigned to `None` without prior `close()`.

### 16 SAFE Cases (True Negatives)
1. `safe_with.py`: Standard `with open(...)` context manager.
2. `safe_close.py`: Deterministic explicit `close()` on single path.
3. `safe_finally.py`: Resource closed inside `finally:` block.
4. `safe_sqlite_with.py`: SQLite context manager.
5. `safe_sqlite_finally.py`: SQLite connection closed in `finally:` block.
6. `safe_alias_close.py`: Handle closed via alias variable (`handle = f; handle.close()`).
7. `safe_reassign_closed.py`: Explicit close before reassignment.
8. `safe_callee_closed.py`: Proven closed by helper in the same module.
9. `safe_with_multi.py`: Compound `with open(...) as a, open(...) as b`.
10. `safe_all_branches_closed.py`: Explicit `close()` in both `if` and `else` branches.
11. `safe_nested_try_finally.py`: Nested try/finally blocks each clean up resources.
12. `safe_multi_resources.py`: Multiple resources, all cleanly closed.
13. `safe_sqlite_context.py`: SQLite transaction context with guaranteed final close.
14. `safe_adversarial_early_return_in_with.py`: Early return inside `with` (context manager auto-closes).
15. `safe_reassign_double_open.py`: Both lifecycle generations closed cleanly.
16. `safe_lookalike_custom.py`: Custom class `open()` method ignored (non-builtin receiver).

### 10 UNKNOWN Cases (Isolated Indeterminate Ownership)
1. `unknown_external_call.py`: Passed to unresolvable external function.
2. `unknown_returned.py`: Resource handle returned to caller.
3. `unknown_stored_attr.py`: Assigned to instance attribute (`self.f = f`).
4. `unknown_stored_container.py`: Appended to data structure (`pool.append(f)`).
5. `unknown_conditional_callee.py`: Callee closes resource only on conditional path.
6. `unknown_imported_callee.py`: Helper imported from another module (unresolvable in AST).
7. `unknown_kwarg_transfer.py`: Passed via keyword argument (`dispatch(resource=f)`).
8. `unknown_subscript_assign.py`: Bound to dictionary key (`registry['db'] = conn`).
9. `unknown_sqlite_transfer.py`: SQLite connection passed to background worker.
10. `unknown_collection_extend.py`: Resources aggregated into list/set (`handles.extend(...)`).

### 4 SYNTAX Cases (Handled Errors)
1. `broken_syntax.py`: Missing colon on function definition (`def broken_code()`).
2. `bad_indentation.py`: Inconsistent indentation (`IndentationError`).
3. `unclosed_parenthesis.py`: Unclosed parenthesis (`open("file.txt"`).
4. `incomplete_try.py`: Try statement without `except` or `finally`.

---

## 6. The Real Bug-Discovery Story: The Loop Early Return Edge Case

The primary value of an adversarial benchmark is that it exposes subtle static analysis weaknesses before production deployment.

### The Adversarial Test Case
```python
def process_records(items):
    f = open("records.txt", "r")
    for item in items:
        if item.is_terminal():
            return -1  # <--- LEAK: Bypasses cleanup!
    f.close()
    return 0
```

### BEFORE: False Negative (Analyzer Blindspot)
- In the initial implementation, `_evaluate_control_flow` traversed `ast.If` and `ast.Try` branches but did not inspect `ast.For`, `ast.AsyncFor`, or `ast.While` loops.
- Because `f.close()` was present at the bottom of the function, the analyzer presumed all execution paths reached `f.close()`.
- **Result:** Classified as `SAFE` (a dangerous False Negative).

### AFTER: Hardened Loop-Aware Analysis
- We updated `_evaluate_control_flow`, `_find_unclosed_exit_detail`, and `_find_unclosed_return_in_stmts` in `analyzer/rules/base_lifecycle.py` to recursively inspect loop bodies and `orelse` clauses.
- Any early `return` or `raise` inside a loop that skips post-loop cleanup is now flagged with full trace details.
- **Result:** Classified as `LEAK` (True Positive) with exact line number and leak path (`Line 2 open() -> Line 5 return -> close() skipped`).

---

## 7. Performance & Resource Footprint

Measurements taken across 10 iterations of the full 46-case benchmark on an Intel/AMD x86_64 host:

| Benchmark Dimension | Measured Value | Unit |
|:---|:---:|:---:|
| **Total Benchmark Run Time** | **0.0632** | seconds |
| **Average Per-File Scan Latency** | **1.37** | milliseconds / file |
| **Analysis Throughput** | **~730** | files / second |
| **Peak Memory Overhead** | **< 14** | megabytes (RAM) |
| **AST Tree Allocation Overhead** | **Transient** | Garbage collected immediately |
| **External Process Spawning** | **0** | Pure in-memory AST |

---

## 8. Determinism Verification

The benchmark includes built-in verification of deterministic execution:
```bash
# Default: Sorted lexical filename execution
python benchmark/run_benchmark.py

# Shuffled with random seed (reproducibility test)
python benchmark/run_benchmark.py --shuffle --seed 42
python benchmark/run_benchmark.py --shuffle --seed 999
```
All runs produce identical confusion matrices, identical counts, and identical exit codes.
