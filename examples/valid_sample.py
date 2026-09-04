"""Example: Valid Python code demonstrating safe resource management."""

import json
from pathlib import Path
from typing import Dict, Any, List


class SafeDataHandler:
    """Demonstrates clean resource handling using context managers."""

    def __init__(self, base_dir: str) -> None:
        self.base_dir = Path(base_dir)

    def read_config(self, filename: str) -> Dict[str, Any]:
        """Safely open and read a JSON configuration file."""
        target = self.base_dir / filename
        with open(target, "r", encoding="utf-8") as file_handle:
            data: Dict[str, Any] = json.load(file_handle)
            return data

    def write_report(self, filename: str, rows: List[str]) -> int:
        """Safely write data rows to an output file."""
        target = self.base_dir / filename
        written_count = 0
        with open(target, "w", encoding="utf-8") as out_handle:
            for row in rows:
                out_handle.write(f"{row}\n")
                written_count += 1
        return written_count


def compute_metrics(values: List[float]) -> Dict[str, float]:
    """Helper function to compute basic metrics."""
    if not values:
        return {"count": 0.0, "mean": 0.0}
    return {
        "count": float(len(values)),
        "mean": sum(values) / len(values),
    }
