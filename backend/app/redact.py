import re

# Compiled regex patterns for common secret formats
SECRET_PATTERNS = [
    # AWS Access Key IDs & Secrets
    (re.compile(r'\b(AKIA[0-9A-Z]{12,32})\b'), r'[REDACTED_AWS_KEY]'),
    (
        re.compile(r'''(?i)\b(aws_secret_access_key|aws_access_key_id|aws_key|aws_secret)\s*=\s*['"][^'"]+['"]'''),
        r'\1 = "[REDACTED_AWS_CREDENTIAL]"',
    ),
    
    # Generic OpenAI / Stripe / standard secret keys starting with sk-
    (re.compile(r'\b(sk-[a-zA-Z0-9_\-]{20,})\b'), r'[REDACTED_SK_KEY]'),
    
    # GitHub Personal Access Tokens and OAuth tokens (ghp_, gho_, ghu_, ghs_, ghr_)
    (re.compile(r'\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b'), r'[REDACTED_GITHUB_TOKEN]'),
    
    # Common assignment patterns for api keys, tokens, secrets
    (
        re.compile(
            r'''(?i)\b(api_key|apikey|secret_key|secret|access_token|auth_token|bearer_token)\s*=\s*['"][^'"]{6,}['"]'''
        ),
        r'\1 = "[REDACTED_API_KEY]"',
    ),
    
    # Common password assignments
    (
        re.compile(
            r'''(?i)\b(password|passwd|db_password|admin_password|secret_password)\s*=\s*['"][^'"]+['"]'''
        ),
        r'\1 = "[REDACTED_PASSWORD]"',
    ),
]


def redact_secrets(code_content: str) -> str:
    """
    Redacts common secret patterns (AWS keys, sk- keys, GitHub tokens,
    hardcoded API keys and passwords) from source code before sending to external LLM APIs.
    
    Note: This is applied ONLY to the copy sent to external LLMs, NEVER
    before Semgrep analysis, allowing Semgrep to identify real secrets.
    """
    redacted = code_content
    for pattern, replacement in SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


if __name__ == "__main__":
    sample = """
    AWS_KEY = "AKIA1234567890EXAMPLE12"
    OPENAI_KEY = "sk-abcdef1234567890abcdef1234567890"
    GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12"
    api_key = "AIzaSyD-sample_secret_key_12345"
    db_password = "SuperSecretAdminPassword123!"
    """
    print("Original:")
    print(sample)
    print("Redacted:")
    print(redact_secrets(sample))
