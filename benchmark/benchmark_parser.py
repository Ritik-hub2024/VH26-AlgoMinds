"""Micro-benchmark for measuring AST parsing throughput."""

import ast
import sys
import time
from pathlib import Path
from typing import List, Tuple

# Ensure project root is in sys.path
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from parser.ast_parser import ASTParser


def collect_sources(directory: Path) -> List[Tuple[str, str, int, int]]:
    """Collect valid Python sources for benchmarking.

    Returns: list of (file_path, source_text, line_count, byte_count).
    """
    sources = []
    for path in directory.rglob("*.py"):
        try:
            rel = path.relative_to(directory)
            if any(part.startswith(".") or part in ("__pycache__", "build", "dist", "venv") for part in rel.parts):
                continue
        except ValueError:
            pass
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            # Verify it parses first so we benchmark valid code
            ast.parse(content, filename=str(path))
            sources.append((str(path), content, len(content.splitlines()), len(content.encode("utf-8"))))
        except (SyntaxError, OSError):
            continue
    return sources


def run_benchmark(target_dir: str, iterations: int = 5) -> None:
    """Benchmark pure AST parsing speed across all valid Python files in target_dir."""
    target_path = Path(target_dir).resolve()
    print(f"\n============================================================")
    print(f"  LeakGuard AST Parser Benchmark")
    print(f"============================================================")
    print(f" Target Directory: {target_path}")
    print(f" Iterations:       {iterations}")

    sources = collect_sources(target_path)
    if not sources:
        print(" [!] No valid Python files found to benchmark.")
        return

    total_files = len(sources)
    total_lines = sum(s[2] for s in sources)
    total_bytes = sum(s[3] for s in sources)

    print(f" Found Files:      {total_files}")
    print(f" Total Lines:      {total_lines:,}")
    print(f" Total Data:       {total_bytes / 1024:.2f} KB")
    print(f"------------------------------------------------------------")

    parser = ASTParser()

    # Warm-up run
    for file_path, source, _, _ in sources:
        parser.parse_source(source, filename=file_path)

    times: List[float] = []
    for it in range(1, iterations + 1):
        t0 = time.perf_counter()
        for file_path, source, _, _ in sources:
            res = parser.parse_source(source, filename=file_path)
            if not res.success:
                raise RuntimeError(f"Unexpected parse failure in {file_path}")
        elapsed = time.perf_counter() - t0
        times.append(elapsed)
        print(f"  Iteration {it}: {elapsed * 1000:.2f} ms")

    best_time = min(times)
    avg_time = sum(times) / len(times)

    throughput_files = total_files / avg_time
    throughput_lines = total_lines / avg_time
    throughput_mb = (total_bytes / (1024 * 1024)) / avg_time

    print(f"------------------------------------------------------------")
    print(f"  Best Time:       {best_time * 1000:.2f} ms")
    print(f"  Average Time:    {avg_time * 1000:.2f} ms")
    print(f"  Throughput:      {throughput_files:.1f} files/sec")
    print(f"                   {throughput_lines:.1f} lines/sec")
    print(f"                   {throughput_mb:.2f} MB/sec")
    print(f"============================================================\n")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else str(_ROOT)
    run_benchmark(target)
