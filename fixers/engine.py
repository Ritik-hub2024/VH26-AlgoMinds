"""Remediation Engine.

Orchestrates automated fix generation, unified diff generation, safe patch application,
file backups, and AST re-scan verification.
"""

import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import cli
from .patch_generator import generate_diff_chunks, generate_unified_diff
from .resource_fixer import ResourceFixer
from .validator import validate_python_syntax


class RemediationEngine:
    """Coordinates fixers, patches, backups, and verification across project files."""

    def __init__(self) -> None:
        self.resource_fixer = ResourceFixer()
        self._fixes: Dict[str, Dict[str, Any]] = {}
        self._backups: Dict[str, str] = {}  # file_path -> original content

    def can_fix(self, finding: Dict[str, Any]) -> bool:
        """Check if an automated fix can be proposed for this finding."""
        return self.resource_fixer.can_fix(finding)

    def generate_fix_for_finding(
        self, file_path: str | Path, finding: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Read source file, generate fix and diff, and return structured fix object."""
        path = Path(file_path).resolve()
        if not path.exists():
            return {
                "success": False,
                "error": f"File not found: {path}",
                "fix_id": None,
                "finding_id": finding.get("id") or f"{finding.get('file')}:{finding.get('line')}",
            }

        try:
            original_code = path.read_text(encoding="utf-8")
        except Exception as e:
            return {
                "success": False,
                "error": f"Could not read file {path}: {e}",
                "fix_id": None,
                "finding_id": finding.get("id") or f"{finding.get('file')}:{finding.get('line')}",
            }

        success, fixed_code, err = self.resource_fixer.generate_fix(original_code, finding)
        if not success or fixed_code is None:
            return {
                "success": False,
                "error": err or "Failed to generate fix.",
                "fix_id": None,
                "finding_id": finding.get("id") or f"{finding.get('file')}:{finding.get('line')}",
            }

        fix_id = f"fix_{uuid.uuid4().hex[:8]}"
        raw_file = finding.get("file") or path.name
        rel_filename = Path(raw_file).name if "/" in raw_file or "\\" in raw_file else raw_file
        diff_data = generate_diff_chunks(original_code, fixed_code, filename=rel_filename)

        fix_record = {
            "fix_id": fix_id,
            "finding_id": finding.get("id") or f"{finding.get('file')}:{finding.get('line')}",
            "file_path": str(path),
            "rel_file": rel_filename,
            "rule_id": finding.get("rule_id", "LEAK001"),
            "line": finding.get("line"),
            "original_code": original_code,
            "modified_code": fixed_code,
            "diff": diff_data,
            "status": "PROPOSED",
            "created_at": time.time(),
            "applied": False,
            "verified": False,
            "verification_message": "",
        }

        self._fixes[fix_id] = fix_record
        return {
            "success": True,
            "fix": fix_record,
            "diff": diff_data,
        }

    def apply_fix(
        self, fix_id: str, base_scan_dir: Optional[Path] = None
    ) -> Dict[str, Any]:
        """Apply a proposed fix to the target file on disk, validate syntax, and re-scan for verification.

        If verification fails, rolls back the file safely.
        """
        if fix_id not in self._fixes:
            return {"success": False, "error": f"Fix ID '{fix_id}' not found."}

        fix = self._fixes[fix_id]
        target_path = Path(fix["file_path"]).resolve()

        if not target_path.exists():
            return {"success": False, "error": f"Target file does not exist: {target_path}"}

        # 1. Create backup
        if str(target_path) not in self._backups:
            try:
                self._backups[str(target_path)] = target_path.read_text(encoding="utf-8")
            except Exception as e:
                return {"success": False, "error": f"Failed to create backup: {e}"}

        # 2. Write modified code
        try:
            target_path.write_text(fix["modified_code"], encoding="utf-8")
        except Exception as e:
            return {"success": False, "error": f"Failed to write patch: {e}"}

        # 3. Validate syntax
        is_valid, syntax_err = validate_python_syntax(fix["modified_code"], filename=target_path.name)
        if not is_valid:
            # Rollback
            self.rollback_fix(str(target_path))
            fix["status"] = "FAILED"
            fix["verification_message"] = f"Syntax validation failed: {syntax_err}"
            return {
                "success": False,
                "error": f"Syntax validation failed after patch: {syntax_err}. Rolled back.",
            }

        # 4. Re-scan for verification
        scan_target = str(base_scan_dir) if base_scan_dir and base_scan_dir.exists() else str(target_path)
        try:
            report = cli.scan_target(scan_target)
        except Exception as e:
            self.rollback_fix(str(target_path))
            return {"success": False, "error": f"Re-scan execution failed: {e}. Rolled back."}

        # Check if the original issue on this file is still detected
        still_present = False
        rel_target = fix["rel_file"]
        for issue in report.issues:
            issue_file = Path(issue.location.file_path).name
            if issue_file == target_path.name or issue.location.file_path.endswith(rel_target):
                # Check line closeness (+/- 5 lines due to indentation / wrapper changes)
                if abs(issue.location.line - fix["line"]) <= 6:
                    still_present = True
                    break

        if still_present:
            # Verification failed: issue remains
            self.rollback_fix(str(target_path))
            fix["status"] = "VERIFICATION_FAILED"
            fix["verified"] = False
            fix["applied"] = False
            fix["verification_message"] = "Issue is still detected by LeakGuard after patch application."
            return {
                "success": False,
                "verified": False,
                "error": "Fix verification failed: LeakGuard scanner still detected the issue after patch. Rolled back.",
            }

        # Verification succeeded!
        fix["status"] = "APPLIED_AND_VERIFIED"
        fix["applied"] = True
        fix["verified"] = True
        fix["verification_message"] = "Issue no longer detected. AST verification passed."

        return {
            "success": True,
            "verified": True,
            "message": "Patch applied and verified cleanly. Issue resolved.",
            "fix": fix,
            "report_summary": {
                "files_scanned": report.files_scanned,
                "clean_files": report.clean_files_count,
                "remaining_leaks": len(report.issues),
                "syntax_errors": len(report.syntax_errors),
            },
        }

    def rollback_fix(self, file_path_str: str) -> bool:
        """Rollback a file to its original backed-up state."""
        if file_path_str in self._backups:
            try:
                Path(file_path_str).write_text(self._backups[file_path_str], encoding="utf-8")
                return True
            except Exception:
                return False
        return False

    def get_fix(self, fix_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve fix by ID."""
        return self._fixes.get(fix_id)

    def get_all_fixes(self) -> List[Dict[str, Any]]:
        """List all generated fixes."""
        return list(self._fixes.values())

    def get_summary(self) -> Dict[str, Any]:
        """Compute remediation stats."""
        total = len(self._fixes)
        verified = sum(1 for f in self._fixes.values() if f.get("verified"))
        applied = sum(1 for f in self._fixes.values() if f.get("applied"))
        files_changed = list({f["rel_file"] for f in self._fixes.values() if f.get("verified")})
        additions = sum(f["diff"]["additions"] for f in self._fixes.values() if f.get("verified") and "diff" in f)
        deletions = sum(f["diff"]["deletions"] for f in self._fixes.values() if f.get("verified") and "diff" in f)

        return {
            "total_fixes": total,
            "applied_fixes": applied,
            "verified_fixes": verified,
            "files_changed": files_changed,
            "lines_added": additions,
            "lines_removed": deletions,
        }
