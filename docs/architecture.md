# LeakGuard — System Architecture Specification

## Overview

LeakGuard is a static analysis platform engineered to detect, explain, and prevent operating system resource leaks (such as unclosed file handles, database connections, and sockets) in Python software before code reaches production.

---

## High-Level System Architecture

```
                     LEAKGUARD
                         |
        +----------------+----------------+
        |                                 |
   Developer UI                        GitHub CI
        |                                 |
   Upload / Paste                    PR / Push
        |                                 |
        +----------------+----------------+
                         |
                    Scan Service
                         |
                    Python AST
                         |
                Analysis Engine
                         |
          +--------------+--------------+
          |              |              |
        SAFE           LEAK          UNKNOWN
          |              |              |
          +--------------+--------------+
                         |
                 AnalysisReport
                  /      |      \
                 /       |       \
             JSON     GitHub      Admin
                       SARIF       DB
                                    |
                              Product Owner
                               Dashboard
```

---

## Architectural Components

### 1. Ingestion Layer
- **Developer Web Interface (`frontend/`, `app.py`)**:
  - Drag-and-drop or file upload for single `.py` scripts.
  - Multi-file directory tree upload for complete project folders.
  - Ephemeral sandbox (`tempfile.TemporaryDirectory()`) isolates uploaded files.
  - Automatic filtering: only `.py` files are processed; non-Python files are rejected safely.
- **CLI & CI Runner (`cli.py`, `.github/workflows/ci.yml`)**:
  - Invoked locally or directly on GitHub Actions Linux/Windows/macOS runners.
  - Supports `--baseline`, `--baseline-out`, `--policy`, `--ci-export`, and `--format`.
  - Deterministic exit codes: `0` (Safe/Tolerated), `1` (Blocking Leak/Syntax Error), `2` (CLI Usage Error).

---

### 2. Pure AST Parsing Engine (`parser/ast_parser.py`)
- Reads raw source text and passes it to Python's standard library `ast.parse()`.
- **Zero Code Execution**: Code is never imported, loaded into `sys.modules`, or executed via `eval()`/`exec()`.
- Catches `SyntaxError` and `IndentationError` gracefully, recording precise line and column offsets without crashing the scan pipeline.

---

### 3. Lifecycle Analysis Engine (`analyzer/rules/base_lifecycle.py`)
- **Resource Allocation Tracking**: Identifies initialization call sites (`open(...)`, `sqlite3.connect(...)`).
- **Control-Flow Path Verification**:
  - **Context Managers (`with`)**: Proves automatic `__exit__` cleanup across all enclosed paths, including early returns.
  - **Exception Handlers (`try / except / finally`)**: Validates that cleanup code resides in guaranteed `finally` blocks rather than error-prone `try` or `except` bodies.
  - **Loop Traversal (`for`, `while`)**: Recursively inspects loop bodies for `return` or `break` statements that skip trailing post-loop cleanup.
  - **Reassignment Detection**: Flags reassigning an existing active handle variable (`f = ...` or `f = None`) without a preceding `close()` call.
  - **Alias Tracking**: Traces variable assignment aliases (`handle = f`) to verify cleanup via aliases.
  - **Same-Module Callee Proof**: Inspects function definitions within the same AST module to prove if a passed resource is closed by a helper.

---

### 4. Classification Triad (SAFE / LEAK / UNKNOWN)
LeakGuard rejects binary guesswork by adopting a sound three-state classification:
- **`SAFE` (True Negative)**: Mathematical proof that every reachable exit path triggers deterministic resource cleanup.
- **`LEAK` (True Positive)**: Concrete proof that at least one reachable exit path exits the scope without closing the resource.
- **`UNKNOWN` (Indeterminate / Escaped)**: The resource escaped local analysis scope (returned to caller, passed to external library, or stored in an instance attribute). Isolated from false alarm statistics.

---

### 5. Differential Baseline & Security Policy Engine (`models/baseline.py`, `models/policy.py`)
- **Finding Fingerprint (5-Tuple)**:
  `{rule_id}:{normalized_relative_path}:{line}:{resource_type}:{resource_name}`
- **Baseline Gating**: Allows teams with legacy codebases to prevent new regressions without getting blocked by existing tech debt.
- **Policy Enforcement**:
  - `HIGH / CRITICAL`: Blocks CI (Exit 1).
  - `MEDIUM / LOW`: Emits warning (Exit 0).
  - `UNKNOWN`: Advisory by default (Exit 0); optionally blocks with `--block-unknown`.

---

### 6. Multi-Channel Reporting & Security Intelligence
- **Console Reporter (`reporter/console.py`)**: Rich color terminal output with causality traces.
- **JSON Reporter (`reporter/json_reporter.py`)**: Machine-readable full analysis payload.
- **GitHub Step Summary (`reporter/markdown.py`)**: Markdown tables with gate impact badges directly in GitHub Actions summaries.
- **OASIS SARIF v2.1.0 (`reporter/sarif.py`)**: Standard security static analysis format compatible with GitHub Code Scanning.
- **Persistent Storage (`storage/database.py`)**: SQLite database (`leakguard.db`) recording scans, health scores, and CI provenance.
- **Admin Dashboard (`frontend/index.html`, `frontend/app.js`)**: Executive overview of portfolio health, CI trends, and drilldown findings.
