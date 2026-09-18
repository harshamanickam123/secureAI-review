import json
import time
import httpx

API_BASE = "http://127.0.0.1:8000"

VULNERABLE_CODE_SAMPLE = """import os
import subprocess

# 1. Insecure hardcoded credential
DB_PASSWORD = "SuperSecretAdminPassword123!"
AWS_KEY = "AKIA1234567890EXAMPLE12"

def execute_user_query(user_query, user_command):
    # 2. SQL Injection via string formatting
    sql = "SELECT * FROM users WHERE username = '%s'" % user_query
    
    # 3. Insecure shell command execution
    os.system("echo " + user_command)
    subprocess.call("ls " + user_command, shell=True)

def authenticate(user, password):
    if password == "admin_hardcoded_token":
        return True
    return False
"""


def test_end_to_end_flow():
    print("=" * 60)
    print("Testing End-to-End SecureAI Review Pipeline via Running Server")
    print("=" * 60)

    # 1. Health check
    res_health = httpx.get(f"{API_BASE}/health")
    print(f"[+] Health check status: {res_health.status_code} -> {res_health.json()}")

    # 2. Submit scan
    payload = {
        "source_type": "paste",
        "content": VULNERABLE_CODE_SAMPLE,
        "language": "python",
    }
    print("\n[+] Submitting vulnerable code snippet to POST /api/scan...")
    res_post = httpx.post(f"{API_BASE}/api/scan", json=payload)
    print(f"[+] POST Status: {res_post.status_code}")
    post_data = res_post.json()
    print(f"[+] POST Response: {post_data}")
    scan_id = post_data["scan_id"]

    # 3. Poll for results
    print(f"\n[+] Polling GET /api/scan/{scan_id} every 2 seconds...")
    max_retries = 30
    final_data = None

    for attempt in range(1, max_retries + 1):
        time.sleep(2)
        res_get = httpx.get(f"{API_BASE}/api/scan/{scan_id}")
        data = res_get.json()
        status = data.get("status")
        print(f"  Attempt {attempt}: status = '{status}'")
        if status in ("done", "error"):
            final_data = data
            break

    if not final_data:
        raise RuntimeError("Scan did not complete within timeout")

    print("\n" + "=" * 60)
    print(f"Final Scan Result (Status: {final_data.get('status')})")
    print("=" * 60)
    print(f"Total Findings Detected: {len(final_data.get('findings', []))}\n")
    for idx, f in enumerate(final_data.get("findings", []), start=1):
        print(f"Finding #{idx}:")
        print(f"  Rule ID           : {f.get('rule_id')}")
        print(f"  Severity          : {f.get('severity')}")
        print(f"  Line Number       : {f.get('line_number')}")
        print(f"  Raw Message       : {f.get('raw_message')}")
        print(f"  AI Explanation    : {f.get('ai_explanation')}")
        print(f"  AI Suggested Fix  : {f.get('ai_fix_suggestion')}")
        print(f"  Severity Conflict : {f.get('severity_conflict')}")
        print("-" * 50)


if __name__ == "__main__":
    test_end_to_end_flow()
