"""LeakGuard GitHub PR Security Experience Simulation Script.

Demonstrates:
1. Baseline Generation (tolerating existing legacy leaks)
2. PR introducing a NEW leak -> PR Gate BLOCKED (Exit 1)
3. PR fixing the new leak -> PR Gate PASSED (Exit 0) with tolerated legacy leaks
4. PR introducing a Syntax Error -> PR Gate BLOCKED (Exit 1)
"""

import os
import sys
import tempfile
from pathlib import Path

# Add project root to sys.path
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from cli import main


def safe_print(text: str) -> None:
    """Print text safely across Windows cp1252 and UTF-8 terminal encodings."""
    try:
        print(text)
    except UnicodeEncodeError:
        encoding = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"
        safe_text = text.encode(encoding, errors="replace").decode(encoding)
        print(safe_text)


def print_banner(title: str, color_code: str = "36") -> None:
    safe_print(f"\n\033[{color_code};1m{'=' * 72}\033[0m")
    safe_print(f"\033[{color_code};1m  {title}\033[0m")
    safe_print(f"\033[{color_code};1m{'=' * 72}\033[0m\n")


def run_simulation() -> None:
    print_banner("LEAKGUARD GITHUB PR SECURITY EXPERIENCE SIMULATION", "35")

    with tempfile.TemporaryDirectory() as tmp_dir:
        work_dir = Path(tmp_dir)
        repo_dir = work_dir / "project"
        repo_dir.mkdir()

        baseline_file = work_dir / "baseline.json"
        summary_file = work_dir / "step_summary.md"

        # -------------------------------------------------------------
        # Step 1: Main branch with legacy existing leak
        # -------------------------------------------------------------
        print_banner("STEP 1: Main Branch — Generating Security Baseline", "34")
        legacy_file = repo_dir / "legacy_storage.py"
        legacy_file.write_text(
            '"""Legacy module with an existing resource leak."""\n\n'
            'def read_legacy_config():\n'
            '    f = open("config.ini", "r")\n'
            '    # Existing legacy leak: missing f.close()\n'
            '    return f.read()\n',
            encoding="utf-8",
        )
        safe_print(f"Created legacy file: {legacy_file.name}")
        safe_print("Generating baseline with: python cli.py --target project/ --baseline-out baseline.json")

        exit_code_gen = main([
            "--target", str(repo_dir),
            "--baseline-out", str(baseline_file),
            "--no-color",
        ])
        safe_print(f"Baseline generated at: {baseline_file} (Initial scan exit code: {exit_code_gen})")

        # -------------------------------------------------------------
        # Step 2: PR #1 introduces a NEW unclosed leak
        # -------------------------------------------------------------
        print_banner("STEP 2: Pull Request #101 — Developer Introduces NEW Leak", "31")
        new_feature_file = repo_dir / "user_service.py"
        new_feature_file.write_text(
            '"""New service introduced in PR #101."""\n\n'
            'def load_user_profile(user_id):\n'
            '    f = open(f"user_{user_id}.json", "r")\n'
            '    if not user_id:\n'
            '        return None  # Early return leak!\n'
            '    data = f.read()\n'
            '    f.close()\n'
            '    return data\n',
            encoding="utf-8",
        )
        safe_print(f"Developer added: {new_feature_file.name} with early-return leak on line 6.")
        safe_print("Running PR check: python cli.py --target project/ --baseline baseline.json --github-summary")

        exit_code_pr1 = main([
            "--target", str(repo_dir),
            "--baseline", str(baseline_file),
            "--github-summary", str(summary_file),
            "--no-color",
        ])

        safe_print(f"\nPR #101 Exit Code: \033[31;1m{exit_code_pr1} (BLOCKED)\033[0m")
        safe_print("\nGenerated GitHub Step Summary:")
        safe_print("-" * 60)
        safe_print(summary_file.read_text(encoding="utf-8"))
        safe_print("-" * 60)
        assert exit_code_pr1 == 1, "Expected PR with new leak to be BLOCKED (exit code 1)"

        # -------------------------------------------------------------
        # Step 3: Developer fixes the new leak
        # -------------------------------------------------------------
        print_banner("STEP 3: Developer Commits Fix — Context Manager Applied", "32")
        new_feature_file.write_text(
            '"""Fixed service using context manager."""\n\n'
            'def load_user_profile(user_id):\n'
            '    if not user_id:\n'
            '        return None\n'
            '    with open(f"user_{user_id}.json", "r") as f:\n'
            '        return f.read()\n',
            encoding="utf-8",
        )
        safe_print("Developer replaced unclosed handle with 'with open(...)'.")
        safe_print("Re-running PR check with baseline...")

        summary_file.unlink()
        exit_code_pr2 = main([
            "--target", str(repo_dir),
            "--baseline", str(baseline_file),
            "--github-summary", str(summary_file),
            "--no-color",
        ])

        safe_print(f"\nPR #101 Re-scan Exit Code: \033[32;1m{exit_code_pr2} (PASSED)\033[0m")
        safe_print("\nUpdated GitHub Step Summary:")
        safe_print("-" * 60)
        safe_print(summary_file.read_text(encoding="utf-8"))
        safe_print("-" * 60)
        assert exit_code_pr2 == 0, "Expected PR with fixed leak to PASS (exit code 0)"

        # -------------------------------------------------------------
        # Step 4: PR with Syntax Error
        # -------------------------------------------------------------
        print_banner("STEP 4: Developer Introduces Syntax Error", "33")
        broken_file = repo_dir / "broken.py"
        broken_file.write_text("def broken_syntax(\n", encoding="utf-8")

        summary_file.unlink()
        exit_code_pr3 = main([
            "--target", str(repo_dir),
            "--baseline", str(baseline_file),
            "--github-summary", str(summary_file),
            "--no-color",
        ])

        safe_print(f"\nPR Syntax Check Exit Code: \033[31;1m{exit_code_pr3} (BLOCKED)\033[0m")
        assert exit_code_pr3 == 1, "Expected syntax error to BLOCK (exit code 1)"
        safe_print("Syntax error correctly blocked the gate despite baseline!")

    print_banner("ALL PR SECURITY EXPERIENCE SCENARIOS VERIFIED SUCCESSFULLY!", "32")


if __name__ == "__main__":
    run_simulation()
