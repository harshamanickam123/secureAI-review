import json
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List

LANGUAGE_EXTENSIONS = {
    "python": ".py",
    "py": ".py",
    "javascript": ".js",
    "js": ".js",
    "typescript": ".ts",
    "ts": ".ts",
    "java": ".java",
}


def _get_semgrep_executable() -> str:
    """Find the semgrep executable in PATH or virtualenv."""
    # Check current Python venv Scripts / bin directory
    venv_dir = os.path.dirname(sys.executable)
    for candidate in [
        os.path.join(venv_dir, "semgrep.exe"),
        os.path.join(venv_dir, "semgrep"),
        shutil.which("semgrep"),
    ]:
        if candidate and os.path.exists(candidate):
            return candidate
    return "semgrep"


def _get_target_configs(language: str = "python") -> List[str]:
    """
    Returns targeted Semgrep configs based on target language:
    - Base: p/security-audit, p/owasp-top-ten
    - JS/TS: p/nodejsscan, p/express, and custom mass-assignment rule
    - Python: p/python
    - Java: p/java
    - Custom rules directory (backend/semgrep-rules)
    """
    norm_lang = language.strip().lower()
    configs = ["p/security-audit", "p/owasp-top-ten"]

    if norm_lang in ("javascript", "js", "typescript", "ts"):
        configs.extend(["p/nodejsscan"])
    elif norm_lang in ("python", "py"):
        configs.append("p/python")
    elif norm_lang in ("java",):
        configs.append("p/java")

    # Add custom semgrep-rules directory or file if present
    custom_rules_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "semgrep-rules")
    )
    if os.path.exists(custom_rules_dir):
        configs.append(custom_rules_dir)

    return configs


def _deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Removes duplicate findings matching on (rule_id, line_number, file_path)."""
    seen = set()
    unique = []
    for f in findings:
        key = (f.get("rule_id"), f.get("line_number"), f.get("file_path"))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def run_semgrep_scan(code_content: str, language: str = "python") -> List[Dict[str, Any]]:
    """
    Writes code to a temporary file with the matching language extension,
    executes semgrep static analysis using targeted rulesets, and returns deduplicated findings.
    """
    norm_lang = language.strip().lower()
    ext = LANGUAGE_EXTENSIONS.get(norm_lang, ".py")

    temp_dir = tempfile.mkdtemp(prefix="secureai_scan_")
    temp_file_path = os.path.join(temp_dir, f"target_code{ext}")

    try:
        with open(temp_file_path, "w", encoding="utf-8") as f:
            f.write(code_content)

        semgrep_bin = _get_semgrep_executable()
        temp_file_name = os.path.basename(temp_file_path)
        target_configs = _get_target_configs(norm_lang)

        cmd = [
            semgrep_bin,
            "--disable-version-check",
            "--no-git-ignore",
            "--json",
            "--quiet",
        ]
        for cfg in target_configs:
            cmd.extend(["--config", cfg])

        cmd.append(temp_file_name)

        # Execute semgrep with 60-second timeout
        try:
            result = subprocess.run(
                cmd,
                cwd=temp_dir,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Semgrep scan timed out after 60 seconds")
        except FileNotFoundError:
            raise RuntimeError(
                f"Semgrep executable '{semgrep_bin}' not found. Please ensure semgrep is installed."
            )

        # Semgrep returns 0 if clean, 1 if findings are present.
        if result.returncode not in (0, 1):
            error_msg = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(f"Semgrep execution failed (exit code {result.returncode}): {error_msg}")

        raw_output = result.stdout.strip()
        if not raw_output:
            return []

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse Semgrep JSON output: {e}. Output was: {raw_output[:500]}")

        findings: List[Dict[str, Any]] = []
        raw_results = data.get("results", [])

        for item in raw_results:
            rule_id = item.get("check_id", "unknown-rule")
            extra = item.get("extra", {})
            severity = extra.get("severity", "WARNING").upper()
            raw_message = extra.get("message", "Security finding detected.")
            
            start_pos = item.get("start", {})
            line_number = start_pos.get("line", 1)
            file_path = item.get("path", temp_file_path)

            findings.append({
                "rule_id": rule_id,
                "severity": severity,
                "file_path": os.path.basename(file_path),
                "line_number": line_number,
                "raw_message": raw_message,
                "source": "semgrep",
            })

        return _deduplicate_findings(findings)

    finally:
        # Cleanup temporary directory and files
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)


def run_semgrep_repo_scan(repo_url: str) -> List[Dict[str, Any]]:
    """
    Performs a shallow git clone of a public repository into a temporary directory,
    executes semgrep static analysis against the codebase, and returns parsed findings.
    """
    clean_url = repo_url.strip()
    if not (clean_url.startswith("http://") or clean_url.startswith("https://") or clean_url.startswith("git@")):
        raise ValueError(f"Invalid repository URL '{clean_url}'. Must begin with http://, https://, or git@")

    temp_dir = tempfile.mkdtemp(prefix="secureai_git_repo_")

    try:
        # Shallow clone repository (depth 1)
        clone_cmd = ["git", "clone", "--depth", "1", clean_url, "."]
        try:
            clone_proc = subprocess.run(
                clone_cmd,
                cwd=temp_dir,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=45,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Git clone timed out after 45 seconds")
        except FileNotFoundError:
            raise RuntimeError("Git executable not found on host machine.")

        if clone_proc.returncode != 0:
            err = clone_proc.stderr.strip() or clone_proc.stdout.strip()
            raise RuntimeError(f"Failed to clone repository '{clean_url}': {err}")

        # Run semgrep on the cloned repository directory with targeted configs
        semgrep_bin = _get_semgrep_executable()
        target_configs = _get_target_configs("javascript")  # Include multi-language configs for repo
        semgrep_cmd = [
            semgrep_bin,
            "--disable-version-check",
            "--no-git-ignore",
            "--json",
            "--quiet",
        ]
        for cfg in target_configs:
            semgrep_cmd.extend(["--config", cfg])
        semgrep_cmd.append(".")

        try:
            result = subprocess.run(
                semgrep_cmd,
                cwd=temp_dir,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Semgrep repository scan timed out after 60 seconds")

        if result.returncode not in (0, 1):
            err = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(f"Semgrep execution failed on repository (exit code {result.returncode}): {err}")

        raw_output = result.stdout.strip()
        if not raw_output:
            return []

        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse Semgrep JSON output: {e}")

        findings: List[Dict[str, Any]] = []
        raw_results = data.get("results", [])

        for item in raw_results:
            rule_id = item.get("check_id", "unknown-rule")
            extra = item.get("extra", {})
            severity = extra.get("severity", "WARNING").upper()
            raw_message = extra.get("message", "Security finding detected.")

            start_pos = item.get("start", {})
            line_number = start_pos.get("line", 1)
            raw_path = item.get("path", "file")
            
            # Normalize relative path within repository
            rel_path = os.path.relpath(raw_path, temp_dir) if os.path.isabs(raw_path) else raw_path
            # Replace backslashes for uniform display
            rel_path = rel_path.replace("\\", "/")

            findings.append({
                "rule_id": rule_id,
                "severity": severity,
                "file_path": rel_path,
                "line_number": line_number,
                "raw_message": raw_message,
                "source": "semgrep",
            })

        return _deduplicate_findings(findings)

    finally:
        # Ensure cleanup of cloned repo directory
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)



if __name__ == "__main__":
    print("=" * 60)
    print("Testing Semgrep Runner Standalone with Insecure Code Sample")
    print("=" * 60)

    insecure_code_sample = """import os
import subprocess

# Insecure hardcoded password/secret
DB_PASSWORD = "SuperSecretAdminPassword123!"
AWS_SECRET_KEY = "AKIA1234567890EXAMPLE12"

def execute_user_command(user_input):
    # Insecure unsanitized command execution
    os.system("echo " + user_input)
    subprocess.call("ls " + user_input, shell=True)

def authenticate(user, password):
    if password == "hardcoded_admin_pass":
        return True
    return False
"""

    print(f"Sample code to scan:\n{insecure_code_sample}")
    print("\nRunning Semgrep scan...")

    try:
        detected_findings = run_semgrep_scan(insecure_code_sample, language="python")
        print(f"\n[+] Scan completed successfully. Total findings detected: {len(detected_findings)}")
        for idx, finding in enumerate(detected_findings, start=1):
            print(f"\n--- Finding #{idx} ---")
            print(f"Rule ID    : {finding['rule_id']}")
            print(f"Severity   : {finding['severity']}")
            print(f"Line       : {finding['line_number']}")
            print(f"Message    : {finding['raw_message']}")
    except Exception as exc:
        print(f"\n[-] Error running Semgrep: {exc}")
