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


