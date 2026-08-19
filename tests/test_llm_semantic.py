from dedup import llm_semantic
from dedup.deterministic import UnionFind
from ingest.schema import Finding


def _finding(**kwargs) -> Finding:
    defaults = dict(scan_id="test", source_scanner="nuclei", host="h", title="t",
                     scanner_severity="medium")
    defaults.update(kwargs)
    return Finding(**defaults)


def test_skips_and_logs_when_llm_unavailable(monkeypatch):
    monkeypatch.setattr(llm_semantic, "is_available", lambda: False)
    findings = [_finding(title="a"), _finding(title="b")]
    uf = UnionFind(len(findings))
    edge_method: dict[frozenset, str] = {}
    log: list[dict] = []

    llm_semantic.resolve_candidates(findings, [(0, 1, 70.0)], uf, edge_method, log)

    assert uf.find(0) != uf.find(1)  # left un-merged, the safe default
    assert not edge_method
    assert len(log) == 1 and "GEMINI_API_KEY not set" in log[0]["note"]


def test_unions_confirmed_duplicates_and_clamps_confidence(monkeypatch):
    monkeypatch.setattr(llm_semantic, "is_available", lambda: True)

    def fake_judge(pairs):
        return [
            {"pair_id": pairs[0]["pair_id"], "is_duplicate": True,
             "confidence": 1.5, "reasoning": "same header issue"},
            {"pair_id": pairs[1]["pair_id"], "is_duplicate": False,
             "confidence": "not-a-number", "reasoning": "different hosts"},
        ]

    monkeypatch.setattr(llm_semantic, "judge_duplicate_pairs", fake_judge)

    findings = [_finding(title="a"), _finding(title="b"),
                _finding(title="c"), _finding(title="d")]
    uf = UnionFind(len(findings))
    edge_method: dict[frozenset, str] = {}
    log: list[dict] = []

    llm_semantic.resolve_candidates(
        findings, [(0, 1, 70.0), (2, 3, 66.0)], uf, edge_method, log)

    assert uf.find(0) == uf.find(1)
    assert edge_method[frozenset((0, 1))] == "llm_semantic"
    assert uf.find(2) != uf.find(3)  # rejected pair stays un-merged

    confirmed = next(e for e in log if e["pair_id"] == "p0")
    rejected = next(e for e in log if e["pair_id"] == "p1")
    assert confirmed["llm_confidence"] == 1.0  # clamped down from 1.5
    assert rejected["llm_confidence"] is None  # non-numeric coerced to None


def test_batch_failure_is_isolated_and_other_batches_still_processed(monkeypatch):
    monkeypatch.setattr(llm_semantic, "is_available", lambda: True)

    def flaky_judge(pairs):
        if pairs[0]["pair_id"] == "p1":  # second batch simulates a transient API error
            raise RuntimeError("quota exceeded")
        return [{"pair_id": pairs[0]["pair_id"], "is_duplicate": True,
                  "confidence": 0.9, "reasoning": "same finding"}]

    monkeypatch.setattr(llm_semantic, "judge_duplicate_pairs", flaky_judge)
    monkeypatch.setattr(llm_semantic, "scoring_config",
                         lambda: {"dedup": {"llm_batch_size": 1}})

    findings = [_finding(title=f"f{i}") for i in range(4)]
    uf = UnionFind(len(findings))
    edge_method: dict[frozenset, str] = {}
    log: list[dict] = []
    candidates = [(0, 1, 70.0), (2, 3, 70.0)]  # two single-pair batches: p0 succeeds, p1 fails

    llm_semantic.resolve_candidates(findings, candidates, uf, edge_method, log)

    assert uf.find(0) == uf.find(1)  # earlier successful batch unaffected by the later failure
    assert uf.find(2) != uf.find(3)  # failed batch left un-merged
    assert any("failed for a batch" in e.get("note", "") for e in log)
