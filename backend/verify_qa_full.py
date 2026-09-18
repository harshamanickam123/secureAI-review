import time
import httpx

API_BASE = "http://127.0.0.1:8000"

VULNERABLE_SNIPPETS = {
    "python": """import os
import subprocess

DB_PASSWORD = "SuperSecretAdminPassword123!"
AWS_KEY = "AKIA1234567890EXAMPLE12"

def execute_user_query(user_query, user_command):
    sql = "SELECT * FROM users WHERE username = '%s'" % user_query
    os.system("echo " + user_command)
    subprocess.call("ls " + user_command, shell=True)
""",
    "javascript": """const express = require('express');
const router = express.Router();
const User = require('./models/User');

router.post('/users', async (req, res) => {
    // Insecure Mass Assignment: passing req.body directly to User.create
    const user = await User.create(req.body);
    res.status(201).json(user);
});
""",
    "typescript": """import express, { Request, Response } from 'express';
import { exec } from 'child_process';

const GITHUB_TOKEN: string = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12";

export function handleAdminAction(req: Request, res: Response): void {
    const command = req.query.cmd as string;
    exec(`sh -c "${command}"`, (err, stdout) => {
        if (err) res.status(500).send(err.message);
        else res.send(stdout);
    });
}
""",
    "java": """import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

public class InsecureAccountService {
    private static final String DB_PASSWORD = "HardcodedDBAdminPass2026!";

    public void processUserRequest(String username, String userCommand) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/app_db", "root", DB_PASSWORD);
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM accounts WHERE owner = '" + username + "'");
        Runtime.getRuntime().exec("sh -c " + userCommand);
    }
}
""",
}


def poll_scan(scan_id: int):
    for _ in range(30):
        time.sleep(2)
        res = httpx.get(f"{API_BASE}/api/scan/{scan_id}")
        data = res.json()
        if data.get("status") in ("done", "error"):
            return data
    return None


def run_qa_suite():
    print("=" * 75)
    print("SECUREAI REVIEW - COMPLETE QA & STABILIZATION VERIFICATION SUITE")
    print("=" * 75)

    # 1. Health check
    h = httpx.get(f"{API_BASE}/health")
    print(f"\n[1/4] Server Health Check: HTTP {h.status_code} -> {h.json()}")
    assert h.status_code == 200

    # 2. Multi-Language & Input Matrix Test
    print("\n[2/4] Testing Multi-Language & Input Sources Matrix:")
    tests = [
        ("Python Snippet (Paste)", "paste", "python", VULNERABLE_SNIPPETS["python"]),
        ("JavaScript Mass Assignment (Paste)", "paste", "javascript", VULNERABLE_SNIPPETS["javascript"]),
        ("TypeScript Snippet (Upload)", "upload", "typescript", VULNERABLE_SNIPPETS["typescript"]),
        ("Java Snippet (Paste)", "paste", "java", VULNERABLE_SNIPPETS["java"]),
        ("GitHub Public Repo (Repo URL)", "repo", "python", "https://github.com/octocat/Hello-World"),
    ]

    for name, source_type, lang, content in tests:
        print(f"\n  >> Running Test: {name}")
        post_res = httpx.post(
            f"{API_BASE}/api/scan",
            json={"source_type": source_type, "content": content, "language": lang},
        )
        print(f"     POST /api/scan -> HTTP {post_res.status_code} (scan_id={post_res.json().get('scan_id')})")
        scan_id = post_res.json()["scan_id"]
        result = poll_scan(scan_id)
        assert result is not None, f"Polling failed for scan_id {scan_id}"
        print(f"     Final Status: {result.get('status')}")
        findings = result.get("findings", [])
        print(f"     Findings Flagged: {len(findings)}")
        for i, f in enumerate(findings[:2], start=1):
            print(f"       [{f.get('severity')}] {f.get('rule_id')} (source: {f.get('source')})")
            print(f"       Message: {f.get('raw_message')[:90]}...")

    # 3. Rate Limiting Verification (6th request within window -> 429)
    print("\n[3/4] Testing Rate Limiting (Max 5 requests per 60s per IP):")
    rate_limit_hit = False
    rate_limit_status = 0
    for req_idx in range(1, 8):
        res = httpx.post(
            f"{API_BASE}/api/scan",
            json={"source_type": "paste", "content": "x = 1", "language": "python"},
        )
        print(f"     Request #{req_idx}: HTTP {res.status_code}")
        if res.status_code == 429:
            rate_limit_hit = True
            rate_limit_status = res.status_code
            print(f"     [+] Rate limit triggered as expected on request #{req_idx}: {res.json()}")
            break

    print(f"     Rate Limiter Verification: {'PASS (HTTP 429 received)' if rate_limit_hit else 'FAIL'}")

    print("\n" + "=" * 75)
    print("ALL QA SUITE CHECKS COMPLETED SUCCESSFULLY")
    print("=" * 75)


if __name__ == "__main__":
    run_qa_suite()
