# LeakGuard AST Parser Benchmarks

This directory contains micro-benchmarking scripts to evaluate the parsing speed and memory overhead of LeakGuard's pure Python AST parser across codebases.

## Running the Benchmark

Benchmark the current repository:
```bash
python benchmark/benchmark_parser.py .
```

Benchmark an external repository or directory:
```bash
python benchmark/benchmark_parser.py /path/to/python/project
```

## Metrics Reported

- **Elapsed Time (ms)**: Best and average run time across configurable iterations.
- **Throughput (files/sec)**: Number of Python files parsed per second.
- **Throughput (lines/sec)**: Lines of Python code parsed per second.
- **Throughput (MB/sec)**: Source data parsed per second.
