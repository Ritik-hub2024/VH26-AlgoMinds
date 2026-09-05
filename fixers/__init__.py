"""LeakGuard Fixers Package.

Provides automated AST-safe code remediation, patch generation, and syntax validation.
"""

from .validator import validate_python_syntax, check_patch_syntax
from .patch_generator import generate_unified_diff, generate_diff_chunks
from .resource_fixer import ResourceFixer
from .engine import RemediationEngine

__all__ = [
    "validate_python_syntax",
    "check_patch_syntax",
    "generate_unified_diff",
    "generate_diff_chunks",
    "ResourceFixer",
    "RemediationEngine",
]
