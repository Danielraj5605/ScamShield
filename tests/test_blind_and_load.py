import json

import pytest

from conftest import needs_artifacts
from scamshield.blind import evaluate_blind, load_blind, wilson


def test_wilson_interval_basics():
    assert wilson(0, 0) == [None, None]
    lo, hi = wilson(50, 100)
    assert 0.40 < lo < 0.41 and 0.59 < hi < 0.60
    lo, hi = wilson(0, 20)
    assert lo == 0.0 and 0.1 < hi < 0.2          # zero errors still has real uncertainty
    lo, hi = wilson(20, 20)
    assert hi == 1.0 and 0.8 < lo < 0.9


def test_load_blind_accepts_common_labels_and_removes_duplicates(tmp_path):
    f = tmp_path / "b.csv"
    f.write_text("text,label\nhello there,genuine\nWin a prize now,SCAM\nWin a prize now,scam\n  ,scam\nsee you,0\npay fee,1\n", encoding="utf-8")
    df = load_blind(f)
    assert len(df) == 4 and df.attrs["duplicates_removed"] == 1
    assert sorted(df.y.tolist()) == [0, 0, 1, 1]


def test_load_blind_rejects_bad_files(tmp_path):
    f = tmp_path / "b.csv"
    f.write_text("message,tag\nhi,ok\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing column"):
        load_blind(f)
    f.write_text("text,label\nhi,maybe\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not 'scam' or 'genuine'"):
        load_blind(f)


@needs_artifacts
def test_blind_evaluation_end_to_end(tmp_path, monkeypatch):
    import scamshield.blind as blind
    monkeypatch.setattr(blind, "REPORTS_DIR", tmp_path)
    f = tmp_path / "b.csv"
    f.write_text("text,label\n"
                 "Your electricity will be disconnected tonight. Call our officer on 9XXXXX1234 immediately,scam\n"
                 "See you at the cafe at six,genuine\n", encoding="utf-8")
    rep = evaluate_blind(f, log=lambda *_: None)
    assert rep["messages"] == 2 and rep["scams"] == 1 and rep["genuine"] == 1
    assert rep["scams_rated_high"]["count"] == 1 and rep["genuine_rated_high"]["count"] == 0
    assert any(p.name.startswith("blind_") for p in tmp_path.iterdir())


def test_loadtest_message_builder_is_new_and_unique():
    from scamshield.loadtest import build_messages
    msgs, unique = build_messages(2000)
    assert len(msgs) == 2000 and unique >= 1500
    assert len(set(msgs)) == unique


@needs_artifacts
def test_loadtest_runs_with_two_workers(tmp_path, monkeypatch):
    import scamshield.loadtest as lt
    monkeypatch.setattr(lt, "REPORTS_DIR", tmp_path)
    rep = lt.run_loadtest(n=300, workers=(1, 2), log=lambda *_: None)
    assert rep["messages"] == 300 and len(rep["runs"]) >= 1
    for run in rep["runs"]:
        assert sum(run["levels"].values()) == 300 and run["messages_per_second"] > 0
    assert json.loads(next(tmp_path.glob("loadtest_*.json")).read_text())["messages"] == 300
