import time
import httpx

API_BASE = "http://127.0.0.1:8000"

MASS_ASSIGNMENT_SNIPPET = """const express = require('express');
const router = express.Router();
const User = require('../models/User');

router.post('/users', async (req, res) => {
    // Insecure Mass Assignment: passing req.body directly to User.create
    const user = await User.create(req.body);
    res.status(201).json(user);
});

router.put('/users/:id', async (req, res) => {
    // Insecure Mass Assignment: passing req.body directly to findByIdAndUpdate
    const updatedUser = await User.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(updatedUser);
});
"""


def test_mass_assignment_scan():
    print("=" * 70)
    print("TESTING EXPRESS/MONGOOSE MASS ASSIGNMENT VULNERABILITY DETECTION")
    print("=" * 70)

    # 1. Submit scan request
    payload = {
        "source_type": "paste",
        "content": MASS_ASSIGNMENT_SNIPPET,
        "language": "javascript",
    }
    print("[+] Submitting Mass Assignment snippet to POST /api/scan...")
    res = httpx.post(f"{API_BASE}/api/scan", json=payload)
    print(f"[+] Response Status: HTTP {res.status_code}")
    data = res.json()
    print(f"[+] Scan Info: {data}")
    scan_id = data["scan_id"]

    # 2. Poll until completion
    print(f"\n[+] Polling GET /api/scan/{scan_id}...")
    for attempt in range(1, 30):
        time.sleep(2)
        poll_res = httpx.get(f"{API_BASE}/api/scan/{scan_id}")
        scan_data = poll_res.json()
        status = scan_data.get("status")
        print(f"  Attempt {attempt}: status = '{status}'")
        if status in ("done", "error"):
            break

    print("\n" + "=" * 70)
    print(f"FINAL SCAN RESULTS (Status: {scan_data.get('status')})")
    print("=" * 70)
    findings = scan_data.get("findings", [])
    print(f"Total Findings Flagged: {len(findings)}\n")

    for idx, f in enumerate(findings, start=1):
        print(f"Finding #{idx}:")
        print(f"  Rule ID           : {f.get('rule_id')}")
        print(f"  Severity          : {f.get('severity')}")
        print(f"  Source            : {f.get('source')} ({'Static Semgrep' if f.get('source') == 'semgrep' else 'AI Independent Audit'})")
        print(f"  File / Line       : {f.get('file_path')}:{f.get('line_number')}")
        print(f"  Raw Message       : {f.get('raw_message')}")
        if f.get("ai_explanation"):
            print(f"  AI Explanation    :\n{f.get('ai_explanation')}")
        if f.get("ai_fix_suggestion"):
            print(f"  AI Suggested Fix  :\n{f.get('ai_fix_suggestion')}")
        print("-" * 60)


if __name__ == "__main__":
    test_mass_assignment_scan()
