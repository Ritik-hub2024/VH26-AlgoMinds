# LeakGuard

> Pure AST-based Python Static Analyzer for Detecting, Explaining, and Gating Operating System Resource Leaks

[![LeakGuard CI](https://github.com/Ritik-hub2024/VH26-AlgoMinds/actions/workflows/ci.yml/badge.svg)](https://github.com/Ritik-hub2024/VH26-AlgoMinds/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://github.com/Ritik-hub2024/VH26-AlgoMinds)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-v2.1.0-green.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

LeakGuard is a lightweight, zero-dependency static analysis platform designed specifically for Python codebases. It inspects Python Abstract Syntax Trees (AST) to identify unclosed file descriptors, dangling database connections, and control-flow anomalies safely, without executing target code or relying on brittle regular expressions.

---

## Table of Contents

1. [The Problem](#1-the-problem)
2. [The Solution](#2-the-solution)
3. [Why Resource Leaks Matter](#3-why-resource-leaks-matter)
4. [Python AST Architecture](#4-python-ast-architecture)
5. [Supported Resource Types](#5-supported-resource-types)
6. [SAFE / LEAK / UNKNOWN Classification Model](#6-safe--leak--unknown-classification-model)
7. [Early Return & Exception Path Analysis](#7-early-return--exception-path-analysis)
8. [Resource Ownership & Inter-Procedural Limitations](#8-resource-ownership--inter-procedural-limitations)
9. [Unified Developer Input: Uploads & Sandboxing](#9-unified-developer-input-uploads--sandboxing)
10. [GitHub Actions CI/CD Integration](#10-github-actions-cicd-integration)
11. [Deterministic Baseline Differential Gating](#11-deterministic-baseline-differential-gating)
12. [Configurable Security Policy](#12-configurable-security-policy)
13. [OASIS SARIF v2.1.0 & GitHub Code Scanning](#13-oasis-sarif-v210--github-code-scanning)
14. [Admin & Product Owner Security Dashboard](#14-admin--product-owner-security-dashboard)
15. [Persistent Scan History & SQLite Storage](#15-persistent-scan-history--sqlite-storage)
16. [Empirical Benchmark Suite (46 Cases)](#16-empirical-benchmark-suite-46-cases)
17. [Accuracy & Generalization Disclaimer](#17-accuracy--generalization-disclaimer)
18. [Security & Zero-Code-Execution Guarantee](#18-security--zero-code-execution-guarantee)
19. [Known Limitations & Roadmap](#19-known-limitations--roadmap)
20. [Quick-Start Instructions](#20-quick-start-instructions)

---

## 1. The Problem

Operating system resources—such as open file descriptors, database connections, and network sockets—are scarce kernel allocations. When developers write Python code, complex control flows (such as early returns, unhandled exception branches, or loop breaks) frequently bypass trailing `close()` invocations. Traditional text-based linters only check for token presence (`open` and `close` keywords), failing to detect control-flow bypasses, while dynamic tests miss rare error paths.

---

## 2. The Solution

LeakGuard performs intra-procedural Abstract Syntax Tree (AST) control-flow graph analysis. It maps the full lifecycle of every acquired resource from its allocation node through conditional branches, exception blocks, and loops. LeakGuard proves whether every reachable path guarantees deterministic cleanup, isolates indeterminate cross-boundary code into `UNKNOWN`, generates SARIF v2.1.0 alerts, and blocks regressions in GitHub Actions with differential baseline gating.

---

## 3. Why Resource Leaks Matter

- **OS Descriptor Exhaustion (`EMFILE: Too many open files`)**: Once a process exhausts available file descriptors, all subsequent file operations, DNS lookups, and incoming socket connections fail globally.
- **Database Connection Pool Starvation**: Unclosed connections leave orphaned transactions, lock tables, and exhaust backend pool limits.
- **Silent Failures in Production**: Resource leaks rarely fail in unit tests where processes terminate quickly. They accumulate in long-running services (FastAPI, Flask, Celery, Django) until cascading outages occur under load.

---

## 4. Python AST Architecture

LeakGuard operates on a decoupled multi-tier architecture:

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

- **Parser Layer (`parser/ast_parser.py`)**: Uses standard library `ast.parse()` to safely convert source code into an AST. Code is never imported or executed.
- **Analysis Engine (`analyzer/engine.py`)**: Coordinates extensible lifecycle rules inheriting from `BaseResourceLifecycleRule`.
- **Lifecycle Engine (`analyzer/rules/base_lifecycle.py`)**: Evaluates control-flow branches, try/finally blocks, loop jumps, variable reassignments, and local aliasing.
- **Domain Models (`models/`)**: Standardized representations for reports, findings, policies, and differential baselines.
- **Reporters (`reporter/`)**: Generates rich terminal output (`console.py`), machine-readable payloads (`json_reporter.py`), PR summaries (`markdown.py`), and SARIF (`sarif.py`).

---

## 5. Supported Resource Types

LeakGuard focuses deeply on Python lifecycle rules:
- **File Descriptors (`LEAK001`)**: Identifies `open()`, `builtins.open()`, and `io.open()`. Verifies cleanup via `with open(...)` or explicit `f.close()` in all execution paths.
- **SQLite Database Connections (`LEAK002`)**: Identifies `sqlite3.connect()`. Verifies cleanup via `conn.close()` in `finally:` blocks or `with contextlib.closing(conn):`.
- **Extensible Registry**: Additional resource rules (e.g. `socket.socket`, `aiohttp.ClientSession`) plug into `RuleRegistry` via the base lifecycle model.

---

## 6. SAFE / LEAK / UNKNOWN Classification Model

LeakGuard rejects binary guesswork and enforces a sound 3-state classification:
- **`SAFE`**: Proves that every reachable control-flow exit path triggers deterministic resource cleanup.
- **`LEAK`**: Proves that at least one reachable exit path terminates without invoking cleanup.
- **`UNKNOWN`**: The resource escaped local analysis scope (returned to caller, passed to external callee, or stored in container/attribute).

```
               Analysis Scope
                     |
        +------------+------------+
        |                         |
   Conclusive Proof          Scope Escape
        |                         |
   +----+----+                    |
   |         |                    |
  LEAK      SAFE               UNKNOWN
  (TP)      (TN)            (Unknown Rate)
```

`UNKNOWN` findings are strictly isolated from False Positive and False Negative metrics. They are treated as advisory notices by default and never trigger false security alarms.

---

## 7. Early Return & Exception Path Analysis

LeakGuard's control-flow graph evaluator detects non-trivial exit points:
- **Early Returns in `if/else`**: Flags branches where one condition returns before `f.close()`.
- **Exception Path Jumps**: Verifies whether unhandled exceptions in `try` blocks skip cleanup placed outside `finally`.
- **Loop Bypasses**: Traverses `ast.For`, `ast.AsyncFor`, and `ast.While` blocks to catch loop early returns that skip post-loop cleanup.
- **Reassignment Leaks**: Detects overwriting a variable (`f = open(...)` or `f = None`) without closing the active handle.

---

## 8. Resource Ownership & Inter-Procedural Limitations

LeakGuard performs intra-procedural analysis with limited same-module callee proof:
- **Same-Module Helpers**: If a function passes a handle to a helper defined in the same AST module (`close_it(f)`), LeakGuard proves if the helper closes the resource.
- **Cross-Module & External Calls**: If a resource is passed to an imported or unresolvable function (`process(f)`), returned (`return f`), or stored on `self.handle`, LeakGuard marks it as `UNKNOWN — Ownership Transferred` with line-level explanation.

---

## 9. Unified Developer Input: Uploads & Sandboxing

LeakGuard provides three developer input methods:
1. **Interactive Paste / Target Select**: Select local workspace directories or paste snippets.
2. **Single Python File Upload**: Upload an individual `.py` script for instant AST analysis.
3. **Project Folder Upload**: Upload a directory tree via `webkitdirectory`. LeakGuard recursively scans `.py` files and ignores non-Python assets (`.txt`, `.json`, binaries).
- **Security Sandboxing**: Uploads are analyzed in ephemeral `tempfile.TemporaryDirectory()` workspaces and unlinked immediately. Absolute paths and path traversals (`..`) are rejected.

---

## 10. GitHub Actions CI/CD Integration

LeakGuard integrates directly into GitHub Actions across Python 3.10, 3.11, 3.12, and 3.13:
```yaml
name: LeakGuard CI
on: [push, pull_request]

jobs:
  test-and-analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -r requirements.txt
      - run: pytest -v
      - run: python cli.py --target . --github-summary
```
**Exit Code Semantics**:
- `exit 0`: Safe code / baseline leaks tolerated -> CI PASS
- `exit 1`: New blocking leaks / syntax errors -> CI FAIL
- `exit 2`: Command-line usage error

---

## 11. Deterministic Baseline Differential Gating

Legacy repositories often contain hundreds of pre-existing leaks. Blocking pull requests on legacy debt frustrates developers. LeakGuard solves this with **deterministic baselines**:

```bash
# 1. Generate baseline snapshot on main branch
python cli.py --target . --baseline-out leak_baseline.json

# 2. Run PR differential check in CI
python cli.py --target . --baseline leak_baseline.json --github-summary
```

### Stable 5-Tuple Fingerprint
```
{rule_id}:{normalized_relative_path}:{line}:{resource_type}:{resource_name}
```
Pre-existing baseline leaks are **tolerated** (Exit 0). Any **new** leak introduced in the PR immediately fails the gate (Exit 1).

---

## 12. Configurable Security Policy

Teams can configure gate thresholds using `--policy` / `--block-level`:
- **`HIGH` (Default)**: Blocks PR on `HIGH` or `CRITICAL` leaks; `MEDIUM` and `LOW` warn.
- **`MEDIUM`**: Blocks PR on `MEDIUM`, `HIGH`, or `CRITICAL` leaks; `LOW` warns.
- **`LOW`**: Blocks PR on any detected issue.
- **`--block-unknown`**: Optional strict mode that blocks on `UNKNOWN` ownership transfers.

---

## 13. OASIS SARIF v2.1.0 & GitHub Code Scanning

LeakGuard generates standard OASIS SARIF v2.1.0 JSON format:
```bash
python cli.py --target . -f sarif -o results.sarif
```

### GitHub Code Scanning Workflow
```yaml
    permissions:
      contents: read
      security-events: write

    steps:
      - name: Run LeakGuard SARIF Scan
        run: python cli.py --target . -f sarif -o results.sarif

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        continue-on-error: true
        with:
          sarif_file: results.sarif
          category: leakguard-python-${{ matrix.python-version }}
```
SARIF paths are normalized relative to `%SRCROOT%`. `UNKNOWN` issues are mapped to `note` severity, ensuring they never trigger false security alarms in GitHub's Security tab.

---

## 14. Admin & Product Owner Security Dashboard

The Admin Dashboard (`/#admin` in the web application) provides an executive portfolio overview:
- **Portfolio Health Table**: Real-time status (`HEALTHY`, `AT_RISK`, `REVIEW`, `NOT_SCANNED`).
- **KPI Summary Cards**: Monitored Projects, Total Scans, Open Leaks, High Severity, and CI Blocked count.
- **CI / PR Intelligence Drilldown**: Inspect repository, branch, commit SHA, PR number, and workflow run ID.
- **New vs. Baseline Separation**: Clear breakdown of blocking new leaks vs. tolerated baseline debt.
- **Zero Fake Data**: Missing metadata is rendered truthfully (`-` or `Not Available`).

---

## 15. Persistent Scan History & SQLite Storage

All scans (local workspace, file upload, project upload, or CI run) are automatically persisted to a local SQLite database (`leakguard.db`):
- Thread-safe storage via Python's standard `sqlite3`.
- Ingest portable CI result JSON artifacts:
  ```bash
  python cli.py --ingest leakguard-ci-result.json
  ```
- REST APIs for portfolio metrics:
  - `GET /api/admin/summary`
  - `GET /api/admin/projects`
  - `GET /api/admin/project?id=<id>`
  - `GET /api/admin/scans?limit=50`
  - `GET /api/admin/analytics`

---

## 16. Empirical Benchmark Suite (46 Cases)

LeakGuard was hardened against a 46-case canonical benchmark corpus:

| Category | File Count | Description |
|:---|:---:|:---|
| **LEAK** | **16** | Early returns, unhandled exceptions, loop skips, reassignments, unclosed SQLite |
| **SAFE** | **16** | Context managers, `finally:` cleanup, alias close, multi-resource with, lookalike methods |
| **UNKNOWN** | **10** | External calls, return transfers, attribute storage, container escapes, kwargs |
| **SYNTAX** | **4** | Missing colons, indentation errors, unclosed parentheses, incomplete try blocks |
| **Total** | **46** | Comprehensive adversarial control-flow evaluation |

### Benchmark Evaluation Results

| Metric | Result | Notes |
|:---|:---:|:---|
| **Precision** | **100.00%** | Zero false positives ($FP = 0$) |
| **Recall** | **100.00%** | Zero false negatives ($FN = 0$) |
| **F1 Score** | **1.0000** | Perfect harmonic mean on definite cases |
| **Definite Accuracy** | **100.00%** | Correct classifications across all definite cases |
| **Unknown Rate** | **21.74%** | 10 / 46 cases safely isolated |
| **Execution Time** | **0.0632s** | Full 46-case benchmark run in ~63 milliseconds |
| **Latency / File** | **1.37 ms** | Average per-file analysis time |

### Running the Benchmark
```bash
# Standard deterministic run
python benchmark/run_benchmark.py

# Shuffled reproducibility test
python benchmark/run_benchmark.py --shuffle --seed 42
```

---

## 17. Accuracy & Generalization Disclaimer

> [!NOTE]
> **Scope of Accuracy Metrics**:
> The 100% precision, 100% recall, and 100% definite accuracy metrics apply **strictly to LeakGuard's curated 46-case canonical benchmark corpus**.
> While the corpus includes adversarial control flows and nested jumps, these results do **not** claim or imply 100% accuracy on arbitrary, dynamic, or metaprogrammed Python code in the wild.
> Indeterminate patterns are isolated into the `Unknown Rate` (21.7%) rather than guessed, ensuring sound and truthful reporting.

---

## 18. Security & Zero-Code-Execution Guarantee

LeakGuard guarantees complete isolation:
- **No Code Execution**: Scanned Python source is parsed via `ast.parse()`. Target code is never imported, loaded into `sys.modules`, or executed with `eval()` or `exec()`.
- **Sandboxed Uploads**: File uploads are processed in ephemeral temporary directories and unlinked immediately.
- **Path Traversal Protection**: Directory traversal sequences (`..`), absolute paths, and null bytes are rejected.

---

## 19. Known Limitations & Roadmap

- **Intra-procedural Focus**: Inter-procedural analysis is limited to callees in the same module. Cross-module inter-procedural proof is classified as `UNKNOWN`.
- **Dynamic Attributes**: Resources assigned to dynamic dictionaries (`locals()[var]`) or injected at runtime cannot be resolved statically.
- **Language Scope**: Exclusively analyzes Python (3.10–3.13). Non-Python languages are out of scope.

---

## 20. Quick-Start Instructions

### Installation
```bash
git clone https://github.com/Ritik-hub2024/VH26-AlgoMinds.git
cd VH26-AlgoMinds
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Run Automated Tests
```bash
# Run full pytest suite (193 tests)
pytest -v

# Run frontend simulation suite (14 tests)
node tests/test_frontend_simulation.js
```

### CLI Scanning
```bash
# Scan a directory
python cli.py --target python/safe/

# Scan with JSON output
python cli.py --target python/leaks/ -f json

# Scan with SARIF export
python cli.py --target python/leaks/ -f sarif -o results.sarif

# Run PR baseline differential check
python cli.py --target python/leaks/ --baseline leak_baseline.json --github-summary
```

### Launch Web & Admin Dashboard
```bash
python app.py
```
Open `http://localhost:8000` in your browser:
- **Developer View**: `http://localhost:8000/#`
- **Admin View**: `http://localhost:8000/#admin`

---

## License

MIT License. Copyright (c) 2026 AlgoMinds / LeakGuard Contributors.
