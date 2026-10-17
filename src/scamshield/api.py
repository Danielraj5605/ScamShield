"""Flask API + web UI. Privacy by default: message text is never logged or stored."""
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
import time
import uuid
from collections import defaultdict, deque

from flask import Flask, g, jsonify, request, send_from_directory

from . import genai
from .config import MAX_CHARS, ROOT, WEB_DIR, env, env_bool, env_int
from .pipeline import ScamShield
from .platform_info import fingerprint, one_line

log = logging.getLogger("scamshield")


class _Metrics:
    def __init__(self):
        self.lock = threading.Lock()
        self.latencies = deque(maxlen=5000)
        self.levels = defaultdict(int)
        self.requests = 0
        self.started = time.time()

    def record(self, ms: float, level: str | None):
        with self.lock:
            self.requests += 1
            self.latencies.append(ms)
            if level:
                self.levels[level] += 1

    def snapshot(self) -> dict:
        with self.lock:
            lat = sorted(self.latencies)
        pct = lambda q: round(lat[min(len(lat) - 1, int(q * len(lat)))], 2) if lat else None
        return {"requests": self.requests, "uptime_s": round(time.time() - self.started),
                "latency_ms": {"p50": pct(0.5), "p95": pct(0.95), "p99": pct(0.99)}, "levels": dict(self.levels)}


class _RateLimiter:
    """Simple per-client token bucket (in memory) to stop abuse of a shared demo server."""

    def __init__(self, per_minute: int):
        self.rate, self.buckets, self.lock = per_minute, {}, threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.time()
        with self.lock:
            tokens, last = self.buckets.get(key, (self.rate, now))
            tokens = min(self.rate, tokens + (now - last) * self.rate / 60)
            if tokens < 1:
                self.buckets[key] = (tokens, now)
                return False
            self.buckets[key] = (tokens - 1, now)
            return True


def _feedback_db(path: str):
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.execute("CREATE TABLE IF NOT EXISTS feedback (ts REAL, text_hash TEXT, verdict TEXT, level TEXT, model TEXT)")
    return conn


def create_app(shield: ScamShield | None = None) -> Flask:
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = 8 * 1024
    shield = shield or ScamShield()
    metrics = _Metrics()
    limiter = _RateLimiter(env_int("SS_RATE_PER_MIN", 120))
    privacy = env_bool("SS_PRIVACY_MODE", True)
    salt = env("SS_FEEDBACK_SALT", "")
    db = _feedback_db(env("SS_DB_PATH", str(ROOT / "feedback.db")))
    db_lock = threading.Lock()
    fp = fingerprint()
    log.info(json.dumps({"event": "startup", "fingerprint": one_line(fp), "model": shield.version,
                         "llm_configured": genai.client().enabled}))

    @app.before_request
    def _start():
        g.t0 = time.perf_counter()
        g.rid = uuid.uuid4().hex[:12]
        if request.path.startswith("/api/") and not limiter.allow(request.remote_addr or "?"):
            return jsonify(error="rate_limited"), 429

    @app.after_request
    def _headers(resp):
        resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Request-Id"] = g.get("rid", "")
        return resp

    def _text_from_request():
        if not request.is_json:
            return None, (jsonify(error="json_required"), 415)
        body = request.get_json(silent=True) or {}
        text = body.get("text")
        if not isinstance(text, str) or not text.strip():
            return None, (jsonify(error="text_required"), 400)
        if len(text) > MAX_CHARS:
            return None, (jsonify(error="too_long", max_chars=MAX_CHARS), 413)
        return text, None

    @app.post("/api/analyze")
    def analyze():
        parsed, err = _text_from_request()
        if err:
            return err
        text = parsed
        result = shield.analyze(text)
        result["request_id"] = g.rid
        ms = (time.perf_counter() - g.t0) * 1000
        metrics.record(ms, result["risk_level"])
        # Log only metadata, never the message itself.
        log.info(json.dumps({"event": "analyze", "rid": g.rid, "chars": len(text), "level": result["risk_level"],
                             "score": result["risk_score"], "ms": round(ms, 2)}))
        return jsonify(result)

    @app.post("/api/explain")
    def explain():
        parsed, err = _text_from_request()
        if err:
            return err
        text = parsed
        result = shield.analyze(text)
        exp = shield.explain(text, result)
        log.info(json.dumps({"event": "explain", "rid": g.rid, "source": exp["source"], "status": exp.get("llm_status")}))
        return jsonify({"explanation": exp, "risk_level": result["risk_level"], "request_id": g.rid})

    @app.post("/api/feedback")
    def feedback():
        body = request.get_json(silent=True) or {}
        verdict, text = body.get("verdict"), body.get("text", "")
        if verdict not in ("correct", "wrong") or not isinstance(text, str) or len(text) > MAX_CHARS:
            return jsonify(error="bad_request"), 400
        if privacy and not salt:
            return jsonify(error="feedback_disabled"), 403
        digest = hashlib.sha256((salt + text.strip().lower()).encode()).hexdigest()
        with db_lock:
            db.execute("INSERT INTO feedback VALUES (?,?,?,?,?)",
                       (time.time(), digest, verdict, str(body.get("level", ""))[:10], shield.version))
            db.commit()
        return jsonify(ok=True)

    @app.get("/api/health")
    def health():
        return jsonify(status="ok", arch=fp["arch"], byteorder=fp["byteorder"], cpus=fp["cpus"],
                       model_version=shield.version, trained_on_arch=shield.meta["trained_on_arch"],
                       neural_model=shield.use_cnn, llm_available=genai.client().available())

    @app.get("/api/metrics")
    def get_metrics():
        return jsonify(metrics.snapshot())

    @app.get("/api/examples")
    def examples():
        return jsonify(json.loads((ROOT / "scripts" / "demo_messages.json").read_text(encoding="utf-8")))

    @app.get("/")
    def index():
        return send_from_directory(WEB_DIR, "index.html")

    @app.get("/static/<path:name>")
    def static_files(name):
        return send_from_directory(WEB_DIR, name)

    @app.errorhandler(413)
    def too_large(_):
        return jsonify(error="too_long", max_chars=MAX_CHARS), 413

    return app
