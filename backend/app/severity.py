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


def cross_check(semgrep_input, ai_input=None) -> bool:
    """
    Compares Semgrep severity against AI severity on a 1-4 ranked scale:
    - Level 1: INFO / LOW
    - Level 2: WARNING / MEDIUM
    - Level 3: ERROR / HIGH
    - Level 4: CRITICAL / BLOCKER

    Accepts both string values and finding dictionaries:
    - cross_check({'severity': 'WARNING'}, {'ai_severity': 'critical'}) -> True (diff: |2 - 4| = 2 >= 2)
    - cross_check('WARNING', 'critical') -> True
    """
    if isinstance(semgrep_input, dict):
        semgrep_sev = semgrep_input.get("severity", "")
    else:
        semgrep_sev = str(semgrep_input) if semgrep_input else ""

    if isinstance(ai_input, dict):
        ai_sev = ai_input.get("ai_severity") or ai_input.get("severity")
    else:
        ai_sev = ai_input

    return check_severity_conflict(semgrep_sev, ai_sev)


if __name__ == "__main__":
    # Test specific user example: cross_check({'severity': 'WARNING'}, {'ai_severity': 'critical'})
    test_result = cross_check({"severity": "WARNING"}, {"ai_severity": "critical"})
    print(f"cross_check({{'severity': 'WARNING'}}, {{'ai_severity': 'critical'}}) => {test_result}")
    assert test_result is True, "Expected cross_check to return True for WARNING vs critical"

    # Additional assertion tests
    assert cross_check("ERROR", "LOW") is True  # 3 vs 1 = diff 2 -> True
    assert cross_check("WARNING", "HIGH") is False  # 2 vs 3 = diff 1 -> False
    assert cross_check("INFO", "CRITICAL") is True  # 1 vs 4 = diff 3 -> True
    assert cross_check("HIGH", "MEDIUM") is False  # 3 vs 2 = diff 1 -> False
    assert cross_check({"severity": "INFO"}, {"ai_severity": "low"}) is False  # 1 vs 1 = diff 0 -> False
    print("All severity cross-check assertions passed successfully.")

