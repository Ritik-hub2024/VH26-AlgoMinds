# LeakGuard: 2-Minute Jury Demo Script

> **Goal**: Demonstrate LeakGuard's intra-procedural AST control-flow analysis live in under 2 minutes:
> **SAFE** -> Introduce early-return leak -> **LEAK DETECTED** -> Fix with context manager -> **SAFE**.

---

## Quick Demo Command

To run the automated walk-through:
```bash
python demo.py
# Or using the multi-runner:
python run.py demo
```

---

## Live Step-by-Step Presentation Guide

### 0:00 - 0:30 | Step 1: Baseline Scan (SAFE)
**Speaker**: *"Welcome. LeakGuard is a pure AST static analyzer for Python that detects resource leaks without executing code or using brittle regexes. Let's start with a clean baseline where a file handle is opened and closed sequentially."*

**Command**:
```bash
python cli.py python/safe_file.py
```
**Expected Output**:
```text
Result: PASSED: All files parsed cleanly. No syntax errors or leaks detected.
```

---

### 0:30 - 1:00 | Step 2 & 3: Introduce Early-Return Leak & Scan (LEAK DETECTED)
**Speaker**: *"Now suppose a developer introduces an early return inside an `if` branch. Notice the pattern: `open -> if condition -> return -> close`. The close at the bottom is bypassed whenever the condition is True."*

**Code Pattern**:
```python
f = open(filename, "r")

if skip:
    return "SKIPPED"  # LEAK! f is never closed here!

header = f.readline()
f.close()
return header
```

**Command**:
```bash
python cli.py python/leak_early_return.py
```
**Expected Output**:
```text
Detected Issues (1):
  [1] [HIGH] LEAK001 in parse_header_or_skip()
      File:           .../python/leak_early_return.py
      Line:           10
      Resource:       f (type: file)
      Problem:        Resource 'f' opened at line 10 is not closed if condition 'skip' at line 12 is met due to early return at line 14.
      Leak Path:      L10: open() -> L12: if skip -> L14: return (leak)
      Recommendation: Use 'with open(...) as f:', or invoke 'f.close()' before returning at line 14.

 Result: FAILED: Resource leaks or syntax errors detected.
```
**Speaker**: *"LeakGuard performs control-flow analysis and catches this immediately. Notice how the report provides all 6 actionable fields: File, Line, Resource, Problem, exact Leak Path, and Recommendation."*

---

### 1:00 - 1:30 | Step 4 & 5: Apply Fix & Verify (SAFE)
**Speaker**: *"Following LeakGuard's recommendation, we refactor the code to use Python's built-in context manager: `with open(...) as f:`. Let's re-scan."*

**Command**:
```bash
python cli.py python/safe_with.py
```
**Expected Output**:
```text
Result: PASSED: All files parsed cleanly. No syntax errors or leaks detected.
```
**Speaker**: *"LeakGuard recognizes `with open(...)` as guaranteed cleanup and verifies the code is clean."*

---

### 1:30 - 2:00 | Step 6: Scope & Boundaries
**Speaker**:
*"To be completely rigorous, we want to be upfront about our scope:*
*1. **Supported**: Intra-procedural AST control flow (sequential code, if/else branching, return/raise statements, try/finally, and with context managers).*
*2. **Explicit Boundary**: Cross-function resource ownership (e.g., allocating a file inside a factory helper or passing it to background tasks across modules) requires inter-procedural call-graph analysis and is **not** claimed to be solved in this version.*
*Thank you!"*

---

## Full Test Suite Verification

Run all automated unit and integration tests:
```bash
python -m pytest -v
```
*(34 of 34 tests passing)*
