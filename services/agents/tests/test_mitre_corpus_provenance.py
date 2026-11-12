"""Regression tests for MITRE corpus provenance in health summaries."""

from __future__ import annotations

from app.tools import mitre_full


def test_unloaded_corpus_is_reported_as_unknown(monkeypatch):
    monkeypatch.setattr(mitre_full, "_loaded", False)
    monkeypatch.setattr(mitre_full, "_source", None)
    monkeypatch.setattr(mitre_full, "_techniques", {})
    monkeypatch.setattr(mitre_full, "_actors", {})
    monkeypatch.setattr(mitre_full, "_tactic_map", {})

    summary = mitre_full.get_coverage_summary()

    assert summary["corpus_loaded"] is False
    assert summary["source"] is None
    assert summary["is_stub"] is False
    assert "nothing" in summary["detail"].lower()


def test_stub_corpus_is_explicitly_identified(monkeypatch):
    monkeypatch.setattr(mitre_full, "_loaded", True)
    monkeypatch.setattr(mitre_full, "_source", mitre_full.SOURCE_STUB)
    monkeypatch.setattr(mitre_full, "_techniques", {})
    monkeypatch.setattr(mitre_full, "_actors", {})
    monkeypatch.setattr(mitre_full, "_tactic_map", {})

    summary = mitre_full.get_coverage_summary()

    assert summary["corpus_loaded"] is True
    assert summary["source"] == mitre_full.SOURCE_STUB
    assert summary["is_stub"] is True
    assert "stub corpus" in summary["detail"].lower()


def test_full_corpus_is_explicitly_identified(monkeypatch):
    monkeypatch.setattr(mitre_full, "_loaded", True)
    monkeypatch.setattr(mitre_full, "_source", mitre_full.SOURCE_FULL)
    monkeypatch.setattr(mitre_full, "_techniques", {})
    monkeypatch.setattr(mitre_full, "_actors", {})
    monkeypatch.setattr(mitre_full, "_tactic_map", {})

    summary = mitre_full.get_coverage_summary()

    assert summary["corpus_loaded"] is True
    assert summary["source"] == mitre_full.SOURCE_FULL
    assert summary["is_stub"] is False
    assert "full" in summary["detail"].lower()
