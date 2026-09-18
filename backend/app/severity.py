from typing import Optional

SEVERITY_SCALE = {
    # Ranked scale 1-4
    "info": 1,
    "low": 1,
    "warning": 2,
    "medium": 2,
    "warn": 2,
    "error": 3,
    "high": 3,
    "critical": 4,
    "blocker": 4,
}


def get_severity_rank(severity_str: Optional[str]) -> int:
    """Returns integer rank (1-4) for a severity level."""
    if not severity_str:
        return 2  # Default to medium/warning
    cleaned = str(severity_str).strip().lower()
    return SEVERITY_SCALE.get(cleaned, 2)


def check_severity_conflict(semgrep_severity: str, ai_severity: Optional[str]) -> bool:
    """
    Compares Semgrep severity against AI severity on a ranked scale
    (low/info=1, medium/warning=2, high/error=3, critical=4).
    Returns True if they disagree by 2 or more levels.
    """
    if not ai_severity:
        return False

    semgrep_rank = get_severity_rank(semgrep_severity)
    ai_rank = get_severity_rank(ai_severity)

    return abs(semgrep_rank - ai_rank) >= 2


if __name__ == "__main__":
    # Tests
    assert check_severity_conflict("ERROR", "LOW") is True  # 3 vs 1 = diff 2 -> True
    assert check_severity_conflict("WARNING", "HIGH") is False  # 2 vs 3 = diff 1 -> False
    assert check_severity_conflict("INFO", "CRITICAL") is True  # 1 vs 4 = diff 3 -> True
    assert check_severity_conflict("HIGH", "MEDIUM") is False  # 3 vs 2 = diff 1 -> False
    print("All severity cross-check assertions passed.")
