from typing import List, Literal, Optional
from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    source_type: Literal["paste", "repo", "upload"] = "paste"
    content: str
    language: str = "python"


class Finding(BaseModel):
    rule_id: str
    severity: str
    file_path: str
    line_number: int
    raw_message: str
    ai_explanation: Optional[str] = None
    ai_fix_suggestion: Optional[str] = None
    ai_confidence: Optional[str] = None
    severity_conflict: Optional[bool] = False
    source: Optional[Literal["semgrep", "ai_only"]] = "semgrep"


class ScanResponse(BaseModel):
    scan_id: int
    status: str
    findings: List[Finding] = Field(default_factory=list)
