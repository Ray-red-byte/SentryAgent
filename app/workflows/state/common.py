from typing import Literal
from dataclasses import dataclass, field

@dataclass
class Vulnerability:
    """Represents a single security vulnerability."""
    type: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    file: str
    line: int
    description: str
    fix_suggestion: str
    cvss_score: float = 0.0
    exploitability: float = 0.0
    fix_available: bool = False
    
    def priority_score(self) -> int:
        """Calculate fix priority based on severity and exploitability."""
        base = {
            "CRITICAL": 100,
            "HIGH": 75,
            "MEDIUM": 50,
            "LOW": 25,
            "INFO": 10
        }[self.severity]
        
        if self.exploitability > 0.8:
            base *= 1.5
        if self.fix_available:
            base *= 1.2
            
        return int(base)


@dataclass
class ScanResult:
    """Results from scanning a single file."""
    file_path: str
    risk_score: int
    routes: int
    hotspots: list[str] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
