"""Security policy definitions for LeakGuard CI/PR checks."""

from enum import Enum
from typing import Dict, Any, Union
from .issue import Severity


class BlockLevel(str, Enum):
    """PR gate blocking severity levels."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


_SEVERITY_SCORES: Dict[str, int] = {
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}

_BLOCK_LEVEL_THRESHOLDS: Dict[BlockLevel, int] = {
    BlockLevel.LOW: 2,      # Blocks on LOW, MEDIUM, HIGH, CRITICAL
    BlockLevel.MEDIUM: 3,   # Blocks on MEDIUM, HIGH, CRITICAL; LOW warns
    BlockLevel.HIGH: 4,     # Blocks on HIGH, CRITICAL; MEDIUM & LOW warn (Default)
}


class SecurityPolicy:
    """Configurable security policy determining which severity levels fail a PR."""

    def __init__(
        self,
        block_level: Union[BlockLevel, str] = BlockLevel.HIGH,
        block_unknown: bool = False,
    ) -> None:
        if isinstance(block_level, str):
            clean_str = block_level.strip().upper()
            try:
                self.block_level = BlockLevel(clean_str)
            except ValueError:
                raise ValueError(
                    f"Invalid block level: '{block_level}'. Expected one of: "
                    f"{', '.join(level.value for level in BlockLevel)}"
                )
        else:
            self.block_level = block_level
        self.block_unknown = block_unknown

    @property
    def threshold(self) -> int:
        """Numeric severity score threshold for blocking."""
        return _BLOCK_LEVEL_THRESHOLDS[self.block_level]

    def _get_severity_score(self, severity: Union[Severity, str]) -> int:
        sev_name = severity.value if isinstance(severity, Severity) else str(severity).upper()
        return _SEVERITY_SCORES.get(sev_name, 1)

    def is_blocking(self, severity: Union[Severity, str]) -> bool:
        """Return True if the issue severity meets or exceeds the blocking threshold."""
        return self._get_severity_score(severity) >= self.threshold

    def is_issue_blocking(self, issue: Any) -> bool:
        """Determine if an issue blocks based on classification and severity."""
        if getattr(issue, "classification", "LEAK") == "UNKNOWN":
            return self.block_unknown
        return self.is_blocking(getattr(issue, "severity", Severity.HIGH))

    def is_warning(self, severity: Union[Severity, str]) -> bool:
        """Return True if the issue does not block but should be flagged as a warning."""
        return not self.is_blocking(severity)

    def to_dict(self) -> Dict[str, Any]:
        """Convert policy configuration to dictionary."""
        return {
            "block_level": self.block_level.value,
            "threshold": self.threshold,
            "block_unknown": self.block_unknown,
        }

    def __repr__(self) -> str:
        bu_str = ", block_unknown=True" if self.block_unknown else ""
        return f"SecurityPolicy(block_level={self.block_level.value}{bu_str})"
