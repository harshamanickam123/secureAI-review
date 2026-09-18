import time
import httpx

API_BASE = "http://127.0.0.1:8000"

CLEAN_SNIPPET = """function calculateDiscount(price, discountPercent) {
    if (typeof price !== 'number' || typeof discountPercent !== 'number') {
        throw new TypeError('Invalid input types');
    }
    if (price < 0 || discountPercent < 0 || discountPercent > 100) {
        throw new RangeError('Values out of range');
    }
    return price - (price * (discountPercent / 100));
}
module.exports = { calculateDiscount };
"""


def test_clean_scan():
    print("=" * 70)
    print("TESTING CLEAN SNIPPET (AI INDEPENDENT AUDIT PASS)")
    print("=" * 70)

    payload = {
        "source_type": "paste",
        "content": CLEAN_SNIPPET,
        "language": "javascript",
    }
    res = httpx.post(f"{API_BASE}/api/scan", json=payload)
    scan_id = res.json()["scan_id"]

    for _ in range(30):
        time.sleep(2)
        poll = httpx.get(f"{API_BASE}/api/scan/{scan_id}").json()
        if poll.get("status") in ("done", "error"):
            print(f"Status: {poll.get('status')}")
            print(f"Total Findings: {len(poll.get('findings', []))}")
            return poll
    return None


if __name__ == "__main__":
    test_clean_scan()
