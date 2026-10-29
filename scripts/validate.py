"""Local checks for the API security gateway.

Talks only to this machine. Confirms the gateway returns the expected
status codes for rate limits, size limits, and allow/deny patterns.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

GATEWAY = "http://127.0.0.1:8080"
API = "http://127.0.0.1:5000"
LOG_PATH = Path(__file__).resolve().parents[1] / "logs" / "access.json"
BURST = 30


def request(url: str, method: str = "GET", data: bytes | None = None, timeout: float = 5.0):
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/octet-stream")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            return resp.status, body
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except OSError as exc:
        return None, str(exc).encode()


def wait_ready(url: str, attempts: int = 30) -> bool:
    for _ in range(attempts):
        status, _ = request(url)
        if status == 200:
            return True
        time.sleep(1)
    return False


def burst(url: str, count: int) -> Counter:
    counts: Counter = Counter()
    for _ in range(count):
        status, _ = request(url)
        counts[status if status is not None else "error"] += 1
    return counts


def summarize(counts: Counter) -> tuple[int, int, int]:
    allowed = sum(counts[code] for code in counts if isinstance(code, int) and 200 <= code < 300)
    blocked = sum(counts[code] for code in (429, 413, 403) if counts[code])
    errors = sum(counts[code] for code in counts if isinstance(code, int) and code >= 500)
    errors += counts["error"]
    return allowed, blocked, errors


def parse_logs() -> Counter:
    events: Counter = Counter()
    if not LOG_PATH.exists():
        return events
    for line in LOG_PATH.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events[json.loads(line).get("security_event", "unknown")] += 1
        except json.JSONDecodeError:
            events["parse_error"] += 1
    return events


def main() -> int:
    print("Waiting for gateway at", GATEWAY, "...")
    if not wait_ready(f"{GATEWAY}/health"):
        print("Gateway is not up. Run: docker compose up --build")
        return 1

    results: list[tuple[str, str, str]] = []
    rules: Counter = Counter()

    status, _ = request(f"{GATEWAY}/api/hello")
    results.append(("normal GET /api/hello", str(status), "pass" if status == 200 else "fail"))

    status, _ = request(f"{GATEWAY}/health")
    results.append(("normal GET /health", str(status), "pass" if status == 200 else "fail"))

    status, _ = request(f"{GATEWAY}/secret")
    results.append(("allowlist GET /secret", str(status), "pass" if status == 403 else "fail"))
    if status == 403:
        rules["allowlist"] += 1

    status, _ = request(f"{GATEWAY}/api/search?q=union%20select")
    results.append(("denylist union select", str(status), "pass" if status == 403 else "fail"))
    if status == 403:
        rules["denylist"] += 1

    status, _ = request(f"{GATEWAY}/api/hello?path=../etc")
    results.append(("denylist path ..", str(status), "pass" if status == 403 else "fail"))
    if status == 403:
        rules["denylist"] += 1

    status, _ = request(f"{GATEWAY}/api/echo", method="POST", data=b"x" * 2048)
    results.append(("size limit 2KB POST", str(status), "pass" if status == 413 else "fail"))
    if status == 413:
        rules["size_limit"] += 1

    print("Waiting 3s for the rate-limit window to refill...")
    time.sleep(3)

    gw_counts = burst(f"{GATEWAY}/api/hello", BURST)
    gw_allowed, gw_blocked, gw_errors = summarize(gw_counts)
    rate_ok = gw_counts[429] > 0 and gw_allowed > 0
    results.append(
        (
            f"rate limit burst x{BURST}",
            f"{gw_allowed} ok / {gw_counts[429]} x429",
            "pass" if rate_ok else "fail",
        )
    )
    rules["rate_limit"] += gw_counts[429]

    time.sleep(1)
    api_counts = burst(f"{API}/api/hello", BURST)
    api_allowed, api_blocked, api_errors = summarize(api_counts)

    print()
    print("API Security Gateway — validation results")
    print("=" * 56)
    print(f"{'Check':<28} {'Status':<22} Result")
    print("-" * 56)
    for name, status, result in results:
        print(f"{name:<28} {status:<22} {result}")

    print()
    print("Burst comparison (30 requests to /api/hello)")
    print("-" * 56)
    print(f"{'Path':<28} {'Allowed':<10} {'Blocked':<10} {'5xx/err':<10} Error rate")
    gw_rate = (gw_errors / BURST) * 100
    api_rate = (api_errors / BURST) * 100
    print(f"{'via gateway :8080':<28} {gw_allowed:<10} {gw_blocked:<10} {gw_errors:<10} {gw_rate:.0f}%")
    print(f"{'direct API :5000':<28} {api_allowed:<10} {api_blocked:<10} {api_errors:<10} {api_rate:.0f}%")
    print()
    print(
        f"Gateway cut API overload errors from {api_rate:.0f}% to {gw_rate:.0f}% "
        f"by returning 429 instead of letting the flood through."
    )

    print()
    print("Rules triggered (this run)")
    print("-" * 56)
    if rules:
        for rule, count in rules.most_common():
            print(f"  {rule:<16} {count}")
    else:
        print("  none")

    events = parse_logs()
    if events:
        print()
        print(f"From {LOG_PATH} (all requests since last log reset)")
        print("-" * 56)
        for event, count in events.most_common():
            print(f"  {event:<16} {count}")

    failed = sum(1 for _, _, result in results if result == "fail")
    print()
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
