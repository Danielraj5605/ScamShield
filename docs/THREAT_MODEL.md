# Threat model

| Threat | Mitigation in this repo | Test |
|---|---|---|
| Users paste personal data | Text is processed in memory; logs contain only metadata (length, level, score, latency). Opt-in feedback stores only `sha256(salt + text)` and is disabled unless a salt is set | `tests/test_api.py::test_message_text_never_logged` |
| Data sent to a third-party LLM | GenAI is off unless configured. When on, only scrubbed text (links/phones/amounts/numbers replaced with placeholders) and the detected warning signs are sent | `tests/test_ensemble_and_genai.py::test_llm_path_with_fake_openai_compatible_server` |
| LLM says something harmful or wrong ("this is safe", a fake helpline, a link) | The LLM never decides the risk level; its output is validated (links, phone numbers other than 1930, contradicting the verdict) and replaced by a template if rejected | `test_validate_rejects_unsafe_llm_output` |
| Clickable scam links in the UI | URLs returned defanged (`hxxp`, `[.]`); the UI renders everything with `textContent` | `test_analyze_schema` |
| XSS through the pasted message | `textContent` only; CSP `default-src 'self'`; `X-Content-Type-Options: nosniff` | `test_security_headers_and_health` |
| Oversized or abusive requests | 2,000-character limit, 8 KB body limit, per-client token-bucket rate limit (120/min by default) | `test_validation` |
| Exposed service on a shared community cloud | Binds to `127.0.0.1`; accessed through an SSH tunnel | — |
| Secrets in git | `.env`, keys, data and artifacts are git-ignored; `.env.example` holds no values | Secret scan before submission |
| Incompatible or tampered model artifacts | Artifacts are never committed; they're trained on the target machine, and loading refuses an architecture mismatch | `ArchMismatchError` in `pipeline.py` |
| Scammers studying the open rules | Accepted risk for a prototype; the learned models carry most of the decision | — |
