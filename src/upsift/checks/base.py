from dataclasses import dataclass
from typing import List, Optional

@dataclass
class Finding:
    id: str
    title: str
    severity: str  # info|low|medium|high|critical
    description: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    references: Optional[list] = None

class BaseCheck:
    id = "base"
    name = "Base Check"
    severity = "info"
    description = "Base"

    def run(self) -> List[Finding]:
        raise NotImplementedError
