import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import numpy as np

from scamshield import genai
from scamshield.ensemble import choose_thresholds, decide_level
from scamshield.signals import CRITICAL, HIGH, MED, Signal

T = {"high": 0.6, "med": 0.3}


def sig(sev):
    return Signal("X", sev, 0.1, "r")


def test_decide_level_bands():
    assert decide_level(0.9, [], T) == "HIGH"
    assert decide_level(0.4, [], T) == "MEDIUM"
    assert decide_level(0.1, [], T) == "LOW"


def test_critical_guardrail_overrides_low_score():
    assert decide_level(0.01, [sig(CRITICAL)], T) == "HIGH"


def test_corroboration_escalates_medium():
    assert decide_level(0.4, [sig(HIGH)], T) == "HIGH"
    assert decide_level(0.4, [sig(MED)], T) == "MEDIUM"
    assert decide_level(0.1, [sig(HIGH)], T) == "LOW"


def test_thresholds_keep_a_medium_band():
    rng = np.random.default_rng(0)
    y = np.r_[np.ones(200), np.zeros(800)]
    s = np.r_[rng.uniform(0.7, 1, 200), rng.uniform(0, 0.3, 800)]
    t = choose_thresholds(y, s)
    assert 0 < t["med"] <= t["high"] * 0.5 + 1e-3  # MEDIUM band always spans at least half of [0, high)
    y2 = np.r_[np.ones(200), np.zeros(800)]
    s2 = np.r_[rng.uniform(0.3, 1, 200), rng.uniform(0, 0.8, 800)]  # overlapping classes
    t2 = choose_thresholds(y2, s2)
    assert 0.2 <= t2["med"] <= t2["high"] * 0.5 + 1e-3


def test_validate_rejects_unsafe_llm_output():
    assert genai.validate("Visit www.sbi.co.in to check.", "HIGH") == "contains_link"
    assert genai.validate("Call 9876543210 now.", "HIGH") == "contains_phone_number"
    assert genai.validate("This message is safe.", "HIGH") == "contradicts_verdict"
    assert genai.validate("This message is not safe. Report it on 1930.", "HIGH") is None


def test_retrieval_prefers_scam_type_card():
    cards = genai.retrieve("your electricity will be cut tonight", "utility")
    assert cards[0].id == "utility" and cards[-1].id == "report"


def test_template_fallback_when_llm_not_configured(monkeypatch):
    monkeypatch.setattr(genai, "_client", None)
    monkeypatch.delenv("SS_LLM_BASE_URL", raising=False)
    out = genai.explain("text", "HIGH", "kyc", ["It threatens to block your account."])
    assert out["source"] == "template" and "KYC" in out["text"]


class _FakeLLM(BaseHTTPRequestHandler):
    reply = "This is a scam because it asks you to update KYC through a link. Do not click it and report it on 1930."

    def do_GET(self):  # /v1/models
        self._send({"data": [{"id": "fake"}]})

    def do_POST(self):  # /v1/chat/completions
        length = int(self.headers["Content-Length"])
        body = json.loads(self.rfile.read(length))
        assert "[link]" in body["messages"][1]["content"] or "Message" in body["messages"][1]["content"]
        assert self.headers.get("Authorization") == "Bearer test-key"
        self._send({"choices": [{"message": {"content": self.reply}}]})

    def _send(self, obj):
        data = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


def test_llm_path_with_fake_openai_compatible_server(monkeypatch):
    server = HTTPServer(("127.0.0.1", 0), _FakeLLM)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        monkeypatch.setenv("SS_LLM_BASE_URL", f"http://127.0.0.1:{server.server_port}/v1")
        monkeypatch.setenv("SS_LLM_API_KEY", "test-key")
        monkeypatch.setenv("SS_LLM_MODEL", "fake")
        monkeypatch.setattr(genai, "_client", None)
        out = genai.explain("update kyc at [link]", "HIGH", "kyc", ["It asks you to update KYC."])
        assert out["source"] == "llm:fake" and out["llm_status"] == "ok"
        _FakeLLM.reply = "Good news, this message is safe."
        out = genai.explain("update kyc at [link]", "HIGH", "kyc", ["It asks you to update KYC."])
        assert out["source"] == "template" and out["llm_status"] == "rejected:contradicts_verdict"
    finally:
        server.shutdown()
        monkeypatch.setattr(genai, "_client", None)
