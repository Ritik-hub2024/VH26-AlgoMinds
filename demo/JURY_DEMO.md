# LeakGuard — 5–7 Minute Jury Demonstration Script

**Target Audience:** Hackathon Jury / Technical Evaluators  
**Estimated Duration:** 5 to 7 minutes  
**Goal:** Prove LeakGuard solves real resource leaks through pure AST static analysis, prevents CI regressions with differential baselines, and gives engineering leadership full visibility without executing target code.

---

## Demo Timeline Overview

```
[0:00 - 0:30]  1. Problem Statement & Why Resource Leaks Matter
[0:30 - 1:30]  2. Live Developer File Upload (Leaking Code)
[1:30 - 2:00]  3. Explainable Findings: Why Flagged, Leak Path, Recommendation
[2:00 - 2:30]  4. Developer Fixes Leak (Context Manager / Finally) & Re-Scans
[2:30 - 3:00]  5. Developer Uploads Whole Project Folder
[3:00 - 3:30]  6. GitHub PR Security Gate: Baseline Differential & Blocking
[3:30 - 4:00]  7. Native GitHub Visibility: Step Summary & SARIF v2.1.0
[4:00 - 5:00]  8. Admin / Product Owner Security Portfolio Dashboard
[5:00 - 5:45]  9. 46-Case Benchmark & The Loop Bug Discovery Story
[5:45 - 6:30] 10. Honest Architecture, Security Guarantees & Conclusion
```

---

## Detailed Step-by-Step Script

### 1. Problem Statement (0:00 – 0:30)
* **Speaker:**
  > "Resource leaks—unclosed files, orphaned database connections, unreleased network sockets—are insidious. They don't crash code immediately during unit tests. They silently exhaust operating system file descriptors in production, leading to midnight server outages and difficult-to-debug crashes.
  > Typical linters look for string matches or require executing tests. LeakGuard takes a different approach: **pure AST static analysis** that proves resource cleanup across every control-flow path."

---

### 2. Developer Uploads a Leaking Python File (0:30 – 1:30)
* **Action:**
  1. Open browser to `http://localhost:8000`.
  2. In the Developer View, click **Upload Python File**.
  3. Select `python/leaks/leak_early_return.py` (or paste leaking code into the dropzone).
* **Speaker:**
  > "Notice what happens instantly. LeakGuard does not run `python my_file.py`—it uses Python's standard `ast.parse()` to build an abstract syntax tree in memory. Within 2 milliseconds, the dashboard flips to **FAILED**."

---

### 3. Explainable Findings (1:30 – 2:00)
* **Action:**
  Scroll to the finding card on screen and highlight the structured sections:
  - **Status:** `[HIGH]`
  - **Resource:** `f (file)`
  - **Why Flagged:** `Resource allocated at line 2 is unclosed on one or more exit paths.`
  - **Leak Path:** `Line 2 open() → Line 5 if error → Line 6 return → close() skipped`
  - **Recommendation:** `Use with open(...) or ensure cleanup in a finally block.`
* **Speaker:**
  > "LeakGuard doesn't just say 'you have a bug'. It provides a deterministic, causal explanation: it tells the developer the exact line of allocation, the branch that skipped cleanup, and the exact remediation to apply."

---

### 4. Developer Fixes the Leak & Re-scans (2:00 – 2:30)
* **Action:**
  1. In Developer View, select target `python/safe/safe_with.py` (or click Upload and choose `safe_with.py`).
  2. Click **Scan Python Project**.
* **Speaker:**
  > "Now the developer wraps the resource in a Python context manager `with open(...) as f:`.
  > LeakGuard scans again. Status: **PASS**. Zero unclosed resources, clean AST parse."

---

### 5. Developer Uploads Project Folder (2:30 – 3:00)
* **Action:**
  1. Click **Upload Python Folder**.
  2. Select the `python/safe/` directory.
* **Speaker:**
  > "When a developer uploads an entire project directory, LeakGuard recursively discovers all `.py` files, automatically ignores non-Python artifacts (`.txt`, `.json`, binaries), isolates syntax errors, and validates the entire codebase in parallel."

---

### 6. GitHub PR Security Gate (3:00 – 3:30)
* **Action:**
  Switch to terminal or open a pre-run simulation:
  ```bash
  python scripts/simulate_pr.py
  ```
* **Speaker:**
  > "How does this prevent regressions in CI?
  > In legacy projects with hundreds of pre-existing leaks, you cannot block every PR for old technical debt. LeakGuard introduces **deterministic baseline gating**.
  > Old leaks in the baseline are tolerated (Exit 0). But the moment a developer introduces a single NEW leak, CI blocks the pull request with Exit 1."

---

### 7. Native GitHub Visibility: Step Summary & SARIF (3:30 – 4:00)
* **Action:**
  Show a generated GitHub Actions job summary (or open `results.sarif` / GitHub Actions run).
* **Speaker:**
  > "In GitHub Actions, LeakGuard writes directly to `GITHUB_STEP_SUMMARY` with status badges, metric tables, and actionable fix recommendations.
  > Furthermore, LeakGuard generates standard **OASIS SARIF v2.1.0**, feeding directly into GitHub Code Scanning alerts with zero third-party dependencies."

---

### 8. Admin / Product Owner Security Portfolio (4:00 – 5:00)
* **Action:**
  1. In the web dashboard, click the **Admin & Product Owner** tab (`/#admin`).
  2. Highlight the **Portfolio Health Table**, the **KPI Cards**, and the **Active Security Gate Policy**.
  3. Click **Details** on a project to inspect the CI Context Card (Commit SHA, PR #, Workflow Run, New vs Baseline leaks).
* **Speaker:**
  > "For engineering managers and product owners, the Admin Dashboard aggregates every scan across the entire company—whether run locally, uploaded through the web, or executed in GitHub Actions.
  > Notice the CI context: commit SHA, PR number, and health score (0–100).
  > And notice the empty state: no fake data. Everything is backed by persistent SQLite storage."

---

### 9. 46-Case Benchmark & The Loop Bug Discovery Story (5:00 – 5:45)
* **Action:**
  Run `python benchmark/run_benchmark.py` in the terminal to show live output:
  ```
  Evaluated 46 test cases: 46 PASS, 0 FAIL.
  Precision: 100%, Recall: 100%, Unknown Rate: 21.7%
  ```
* **Speaker:**
  > "We didn't just build a demo; we evaluated LeakGuard against a **46-case benchmark**: 16 leaks, 16 safe patterns, 10 unknown ownership transfers, and 4 syntax errors.
  > And here is proof of genuine engineering: while designing adversarial benchmark cases, we discovered a real analyzer bug!
  > If a function had an early `return` inside a `for` loop, our initial analyzer missed it because `close()` existed after the loop.
  > Because of the benchmark, we caught this weakness, updated loop-aware control flow in `base_lifecycle.py`, and now detect loop early exits reliably."

---

### 10. Conclusion & Honest Architecture (5:45 – 6:15)
* **Speaker:**
  > "Finally, our architectural integrity guarantees:
  > 1. **Zero code execution:** Malicious or broken code is never imported or run.
  > 2. **Truthful static analysis:** When resources escape across unresolvable boundaries, we classify them as **UNKNOWN**, never guessing.
  > 3. **Sub-second performance:** 46 files analyzed in 63 milliseconds.
  > Thank you, and we welcome your questions!"
