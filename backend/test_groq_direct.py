import os
import json
import httpx
from dotenv import load_dotenv

load_dotenv()

key = os.getenv("GROQ_API_KEY")
print("Key length:", len(key) if key else 0)

headers = {
    "Authorization": f"Bearer {key}",
    "Content-Type": "application/json",
}
payload = {
    "model": "openai/gpt-oss-120b",
    "messages": [
        {"role": "user", "content": 'Output JSON: {"test": "hello"}'}
    ],
    "response_format": {"type": "json_object"},
}

res = httpx.post("https://api.groq.com/openai/v1/chat/completions", headers=headers, json=payload)
print("Status Code:", res.status_code)
print("Response:", res.text)
