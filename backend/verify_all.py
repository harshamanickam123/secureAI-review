import time
import httpx

API_BASE = "http://127.0.0.1:8000"

TEST_CASES = [
    {
        "name": "1. Python Sample Scan",
        "source_type": "paste",
        "language": "python",
        "content": """import os
import subprocess

DB_PASSWORD = "SuperSecretAdminPassword123!"
AWS_KEY = "AKIA1234567890EXAMPLE12"

def execute_user_query(user_query, user_command):
    sql = "SELECT * FROM users WHERE username = '%s'" % user_query
    os.system("echo " + user_command)
    subprocess.call("ls " + user_command, shell=True)
""",
    },
    {
        "name": "2. JavaScript Sample Scan",
        "source_type": "paste",
        "language": "javascript",
        "content": """const express = require('express');
const { exec } = require('child_process');
const app = express();

const JWT_SECRET = "super_secret_jwt_signing_key_98765";

app.get('/search', (req, res) => {
    const userInput = req.query.q;
    eval("console.log('" + userInput + "')");
    exec("ping -c 1 " + userInput, (err, stdout) => {
        res.send(stdout);
    });
});
""",
    },
    {
        "name": "3. File Upload Simulation (.ts file)",
        "source_type": "upload",
        "language": "typescript",
        "content": """import express, { Request, Response } from 'express';
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
    },
    {
        "name": "4. Java Sample Scan",
        "source_type": "paste",
        "language": "java",
        "content": """import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

public class InsecureAccountService {
    private static final String DB_PASSWORD = "HardcodedDBAdminPass2026!";

    public void processUserRequest(String username, String userCommand) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/app_db", "root", DB_PASSWORD);
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE username = '" + username + "'");
        Runtime.getRuntime().exec("sh -c " + userCommand);
    }
}
""",
    },
    {
        "name": "5. GitHub Repo Shallow Clone & Scan",
        "source_type": "repo",
        "language": "python",
        "content": "https://github.com/octocat/Hello-World",
    },
]


def poll_scan(scan_id: int):
    for _ in range(30):
        time.sleep(2)
        res = httpx.get(f"{API_BASE}/api/scan/{scan_id}")
        data = res.json()
        if data.get("status") in ("done", "error"):
            return data
    return None


def run_tests():
    print("=" * 70)
    print("SECUREAI REVIEW - MULTI-LANGUAGE & MULTI-INPUT INTEGRATION TEST SUITE")
    print("=" * 70)

    # Health check
    h = httpx.get(f"{API_BASE}/health")
    print(f"\n[+] Health Check: {h.status_code} -> {h.json()}")

    for test in TEST_CASES:
        print("\n" + "-" * 60)
        print(f"RUNNING: {test['name']}")
        print(f"  Source Type : {test['source_type']}")
        print(f"  Language    : {test['language']}")
        print(f"  Content Ref : {test['content'][:60]}...")

        post_res = httpx.post(
            f"{API_BASE}/api/scan",
            json={
                "source_type": test["source_type"],
                "content": test["content"],
                "language": test["language"],
            },
        )
        print(f"  POST Response : HTTP {post_res.status_code} -> {post_res.json()}")
        scan_id = post_res.json()["scan_id"]

        print(f"  Polling scan #{scan_id}...")
        result = poll_scan(scan_id)
        if not result:
            print("  [-] ERROR: Polling timed out.")
            continue

        print(f"  Status        : {result.get('status')}")
        findings = result.get("findings", [])
        print(f"  Total Findings: {len(findings)}")

        for idx, f in enumerate(findings[:3], start=1):
            print(f"    * Finding #{idx}: [{f.get('severity')}] {f.get('rule_id')} ({f.get('file_path')}:{f.get('line_number')})")
            print(f"      Message: {f.get('raw_message')[:100]}...")


if __name__ == "__main__":
    run_tests()
