"""Secondary semantic-dedup pass: sends fuzzy-ambiguous candidate pairs to Gemini
for a duplicate/not-duplicate judgment, unions confirmed duplicates, and logs
every decision (including rejections) for explainability. Degrades gracefully —
if GEMINI_API_KEY isn't set, this pass is skipped and candidates are left
un-merged (under-merging is the safe default without a judgment call).
"""
from __future__ import annotations

from ai.client import is_available
from ai.dedup_prompt import judge_duplicate_pairs
from dedup.deterministic import UnionFind
from ingest.schema import Finding

_BATCH_SIZE = 10


def resolve_candidates(findings: list[Finding], candidates: list[tuple[int, int, float]],
                        uf: UnionFind, edge_method: dict[frozenset, str],
                        log: list[dict]) -> None:
    if not candidates:
        return

    if not is_available():
        log.append({
            "note": f"Skipped LLM semantic pass for {len(candidates)} candidate pair(s): "
                    "GEMINI_API_KEY not set. Candidates left un-merged."
        })
        return

    id_to_pair = {}
    batch_input = []
    for idx, (i, j, score) in enumerate(candidates):
        pair_id = f"p{idx}"
        id_to_pair[pair_id] = (i, j, score)
        fi, fj = findings[i], findings[j]
        batch_input.append({
            "pair_id": pair_id, "host": fi.host,
            "title_a": fi.title, "desc_a": fi.description,
            "title_b": fj.title, "desc_b": fj.description,
        })

    for start in range(0, len(batch_input), _BATCH_SIZE):
        chunk = batch_input[start:start + _BATCH_SIZE]
        try:
            verdicts = judge_duplicate_pairs(chunk)
        except Exception as e:  # e.g. rate limit/quota exhaustion, transient API errors
            log.append({
                "note": f"LLM semantic pass failed for a batch of {len(chunk)} pair(s): {e}. "
                        "Those candidates are left un-merged; earlier batches in this run "
                        "(if any) are unaffected."
            })
            continue
        for v in verdicts:
            pair_id = v.get("pair_id")
            if pair_id not in id_to_pair:
                continue
            i, j, fuzzy_score = id_to_pair[pair_id]
            is_dup = bool(v.get("is_duplicate"))
            log.append({
                "pair_id": pair_id,
                "finding_a": findings[i].finding_id, "title_a": findings[i].title,
                "finding_b": findings[j].finding_id, "title_b": findings[j].title,
                "fuzzy_score": fuzzy_score,
                "llm_verdict": is_dup,
                "llm_confidence": v.get("confidence"),
                "llm_reasoning": v.get("reasoning"),
            })
            if is_dup:
                uf.union(i, j)
                edge_method[frozenset((i, j))] = "llm_semantic"
