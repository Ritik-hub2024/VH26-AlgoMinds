# LeakGuard — Final Jury Q&A Preparation

**Purpose:** Rapid, precise, and authoritative answers to the most probable and challenging technical questions from the hackathon jury.

---

### Q1: What makes LeakGuard unique?
**Answer:**  
LeakGuard specifically tracks **resource lifecycles through Python AST control-flow graphs** instead of treating code as flat text or relying on simple keyword matching for `open()` and `close()`. It tracks the resource from its allocation node through conditional branches, exception handlers (`try/except/finally`), and loop jumps, proving whether every reachable exit closes the descriptor. Furthermore, it directly bridges developer feedback with CI differential baseline gating and executive portfolio visibility.

---

### Q2: Why Python?
**Answer:**  
Python is heavily used for data pipelines, backend APIs, and microservices where long-running processes frequently suffer from unclosed file descriptor leaks and database connection pool exhaustion. Focusing on Python allowed us to build a deep, mathematically sound intra-procedural AST analyzer using Python's native `ast` library within the hackathon timeframe, without spreading analysis thin across half-implemented language runtimes.

---

### Q3: Why not just use a normal SAST tool (e.g. Bandit, SonarQube, Flake8)?
**Answer:**  
General-purpose linters and SAST tools look for generic security vulnerabilities (like hardcoded secrets, SQL injection, or AST anti-patterns) and often only check if `close()` is called somewhere in the function body. They miss subtle control-flow leaks such as early returns before cleanup, unhandled exceptions inside nested try blocks, loop break exits, and variable reassignment leaks. LeakGuard is a specialized lifecycle analyzer that reconstructs the actual execution path, explains the failure causal chain, and provides a zero-execution guarantee.

---

### Q4: What happens across function boundaries?
**Answer:**  
LeakGuard performs limited inter-procedural reasoning for callees defined within the same module (e.g., helper functions that take a resource handle and guarantee its closure). However, when a resource escapes local scope—such as being returned to an unknown caller, passed to an external library, or stored in a persistent container—LeakGuard classifies the finding as **UNKNOWN (Ownership Transferred)** rather than making a false assumption. This preserves static analysis truthfulness and prevents false alarms.

---

### Q5: Is your tool 100% accurate?
**Answer:**  
No universal claim is made. On our curated **46-case canonical benchmark corpus**, LeakGuard achieved 100% precision and 100% recall on definite decisions, with 21.7% (10 cases) intentionally isolated as `UNKNOWN` due to scope limitations. We do not claim 100% accuracy on arbitrary, dynamic, or metaprogrammed Python code in the wild. Our goal is high confidence and zero false security errors on definite intra-procedural patterns.

---

### Q6: Does LeakGuard execute user code?
**Answer:**  
**No. Absolutely not.** Scanned Python source code is parsed strictly into an Abstract Syntax Tree via Python's standard `ast.parse()`. Code is never imported, never loaded into the Python runtime, and never evaluated via `eval()`, `exec()`, or `subprocess`. Malicious code, infinite loops, and broken scripts can be scanned safely without side effects.

---

### Q7: Why would an enterprise or engineering team adopt LeakGuard?
**Answer:**  
Because it shifts resource leak remediation from 3:00 AM production incident triage into early pull request reviews. With **deterministic baseline gating**, an enterprise with 500 legacy files doesn't have to fix all historic leaks on day one—they establish a baseline and prevent developers from adding even one new leak. It integrates seamlessly with GitHub Actions, outputs standard SARIF v2.1.0, and gives engineering leadership an instant security portfolio score.

---

### Q8: What was an actual weakness or bug you discovered during development?
**Answer:**  
During the expansion of our benchmark to 46 adversarial cases, we created a test case where a function exited early via a `return` statement inside a `for` loop, while `f.close()` was placed after the loop. Our initial control-flow evaluator only traversed `if` and `try` statements and skipped loop blocks, mistakenly classifying the leaking code as `SAFE`. Because our benchmark actively challenged the engine, we caught this weakness, added recursive loop traversal in `analyzer/rules/base_lifecycle.py`, and transformed a False Negative into a verified True Positive.
