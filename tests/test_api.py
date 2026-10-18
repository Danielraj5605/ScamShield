import json
import logging

import pytest

from conftest import ROOT, needs_artifacts

pytestmark = needs_artifacts


@pytest.fixture(scope="module")
def client(shield):
    from scamshield.api import create_app
    app = create_app(shield)
    app.testing = True
    return app.test_client()


def test_analyze_schema(client):
    r = client.post("/api/analyze", json={"text": "Your SBI KYC expires today, update at http://sbi-kyc.top/login"})
    assert r.status_code == 200
    d = r.get_json()
    for key in ("risk_level", "risk_score", "reasons", "advice", "signals", "model_version", "disclaimer", "highlights"):
        assert key in d
    assert d["risk_level"] == "HIGH"
    assert all("[.]" in u for u in d["signals"]["urls"])  # links are defanged


@pytest.mark.parametrize("payload,status", [({"text": ""}, 400), ({"text": "x" * 2001}, 413), ({}, 400)])
def test_validation(client, payload, status):
    assert client.post("/api/analyze", json=payload).status_code == status


def test_non_json_rejected(client):
    assert client.post("/api/analyze", data="text=hi").status_code == 415


def test_security_headers_and_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and "arch" in r.get_json()
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]


def test_explain_falls_back_without_llm(client, monkeypatch):
    from scamshield import genai
    monkeypatch.setattr(genai, "_client", None)
    monkeypatch.delenv("SS_LLM_BASE_URL", raising=False)
    r = client.post("/api/explain", json={"text": "You are under digital arrest. Stay on the video call."})
    d = r.get_json()
    assert d["risk_level"] == "HIGH" and d["explanation"]["source"] == "template"


def test_message_text_never_logged(client, caplog):
    secret = "UNIQUE-SECRET-TEXT-7731 please share your otp"
    with caplog.at_level(logging.INFO, logger="scamshield"):
        client.post("/api/analyze", json={"text": secret})
        client.post("/api/explain", json={"text": secret})
    assert "UNIQUE-SECRET-TEXT-7731" not in caplog.text


def test_ui_and_pages_served(client):
    for path, marker in [("/", b"Check a message for scam warning signs"), ("/how-it-works", b"How it works"),
                         ("/privacy", b"Privacy policy"), ("/terms", b"Terms and conditions")]:
        r = client.get(path)
        assert r.status_code == 200 and marker in r.data, path
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/style.css").status_code == 200


def test_favicons_and_fonts_served(client):
    for path, kind in [("/favicon.svg", "svg"), ("/favicon.ico", "icon"), ("/apple-touch-icon.png", "png"),
                       ("/static/fonts/Inter-400-Latin.woff2", "font"), ("/static/grid.svg", "svg")]:
        r = client.get(path)
        assert r.status_code == 200 and len(r.data) > 100, path


def test_content_security_policy_is_strict(client):
    csp = client.get("/").headers["Content-Security-Policy"]
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert "frame-ancestors 'none'" in csp and "default-src 'self'" in csp


def test_unknown_page_is_404(client):
    assert client.get("/admin").status_code == 404
    assert client.get("/static/../src/scamshield/api.py").status_code in (400, 404)


def test_demo_messages_behave_as_documented(shield):
    """End-to-end check of every message used in the live demo ('MEDIUM+' means MEDIUM or higher)."""
    order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    demos = json.loads((ROOT / "scripts" / "demo_messages.json").read_text(encoding="utf-8"))
    wrong = []
    for d in demos:
        got, exp = shield.analyze(d["text"])["risk_level"], d["expect"]
        ok = order[got] >= order[exp[:-1]] if exp.endswith("+") else order[got] <= order[exp[:-1]] if exp.endswith("-") else got == exp
        if not ok:
            wrong.append((d["label"], exp, got))
    assert not wrong, wrong


def test_pages_and_styles_are_always_revalidated(client):
    for path in ("/", "/how-it-works", "/static/style.css", "/static/app.js"):
        assert "no-cache" in client.get(path).headers.get("Cache-Control", ""), path
