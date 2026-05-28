from __future__ import annotations
 
import difflib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

class RiskLevel(str , Enum):
    READ_ONLY = "read_only"
    REVERSIBLE  = "reversible"
    DESTRUCTIVE = "destructive"


@dataclass
class ClassificationResult:
    level: RiskLevel
    reason: str
    used_llm: bool = False
    escalation_signals: list[str] = field(default_factory=list)


@dataclass
class FileDiff:
    path:Path
    action:str  # created | modified | deleted
    old_content: str | None
    new_content: str | None

    @property
    def unified_diff(self) -> str:
        old_lines = (self.old_content or "").splitlines(keepends=True)
        new_lines = (self.new_content or "").splitlines(keepends=True)

        diff = difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile=f"a/{self.path}",
            tofile=f"b/{self.path}",
        )
        return "".join(diff)
    
    def __str__(self) -> str:
        return f"[{self.action.upper()}] {self.path}"
    

@dataclass
class SandboxResult:
    
    stdout: str
    strerr: str
    exit_code: int
    diffs: list[FileDiff]
    
    upper_dir: Path # Path to the tmpfs upper layer (alive until commit or discard)
    _mount_point: Path | None = field(default=None, repr=False) # tmpfs mount point to umount on cleanup
 
    @property
    def has_changed(self) -> bool:
        return len(self.diffs) > 0
    
    def summary(self) -> str:
        lines = []
        for diff in self.diffs:
            lines.append(str(diff))
        return "\n".join(lines) if lines else "(no filesystem changes)"


@dataclass
class ExecutionResult:
    command: str
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int
    risk_level: RiskLevel
    timed_out: bool = False
    resource_killed: bool = False
    sandboxed: bool = False
    committed: bool = False
    diffs: list[FileDiff] | None = None

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.resource_killed
 
    def __str__(self) -> str:
        status = "OK" if self.success else f"FAIL(exit={self.exit_code})"
        return f"[{self.risk_level.value}] {self.command!r} -> {status} in {self.duration_ms}ms"

