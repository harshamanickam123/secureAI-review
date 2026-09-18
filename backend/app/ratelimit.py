import time
from collections import defaultdict
from typing import Dict, List
from fastapi import HTTPException, Request, status

# In-memory sliding window store: ip_address -> list of request timestamps
_request_history: Dict[str, List[float]] = defaultdict(list)

MAX_REQUESTS_PER_WINDOW = 5
WINDOW_SECONDS = 60.0


def check_rate_limit(request: Request) -> None:
    """
    Enforces in-memory sliding window rate limiting.
    Allows a maximum of 5 requests per 60-second window per IP.
    Raises HTTPException(429) if exceeded.
    """
    # Extract client IP address (supporting X-Forwarded-For when behind proxy)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
    elif request.client:
        client_ip = request.client.host
    else:
        client_ip = "unknown_client"

    now = time.time()
    window_start = now - WINDOW_SECONDS

    # Clean old requests outside current window
    history = [ts for ts in _request_history[client_ip] if ts > window_start]

    if len(history) >= MAX_REQUESTS_PER_WINDOW:
        retry_after = int(WINDOW_SECONDS - (now - history[0])) + 1
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded: maximum {MAX_REQUESTS_PER_WINDOW} requests per {int(WINDOW_SECONDS)} seconds. Please retry after {retry_after}s.",
            headers={"Retry-After": str(retry_after)},
        )

    # Record current request timestamp
    history.append(now)
    _request_history[client_ip] = history
