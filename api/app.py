"""Tiny demo API sitting behind the NGINX security gateway."""

from collections import deque
from threading import Lock
import time

from flask import Flask, jsonify, request

app = Flask(__name__)

# Naive overload guard so a direct flood returns 503s. The gateway
# rate-limits first, so those 503s mostly disappear when traffic goes
# through NGINX.
_hits = deque()
_lock = Lock()
WINDOW_SECONDS = 1.0
MAX_PER_WINDOW = 12


def overloaded() -> bool:
    now = time.monotonic()
    with _lock:
        while _hits and now - _hits[0] > WINDOW_SECONDS:
            _hits.popleft()
        if len(_hits) >= MAX_PER_WINDOW:
            return True
        _hits.append(now)
        return False


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.get("/api/hello")
def hello():
    if overloaded():
        return jsonify({"error": "overloaded"}), 503
    return jsonify({"message": "hello"})


@app.get("/api/search")
def search():
    if overloaded():
        return jsonify({"error": "overloaded"}), 503
    return jsonify({"q": request.args.get("q", ""), "results": []})


@app.post("/api/echo")
def echo():
    if overloaded():
        return jsonify({"error": "overloaded"}), 503
    return jsonify({"bytes": len(request.get_data())})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
