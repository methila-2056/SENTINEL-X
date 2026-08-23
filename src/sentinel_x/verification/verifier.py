"""Finding verification: claim grounding against collected evidence."""

from __future__ import annotations

import json
import re
from typing import Any

EVIDENCE_ID_PATTERN = re.compile(
    r"\b(?:T\d{4}(?:\.\d{3})?|TA\d{4}|CAPEC-\d+|CVE-\d{4}-\d{4,7}"
    r"|FORMED-[A-Za-z0-9-]+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b"
)
SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+")


def _extract_cited_ids(text: str) -> set[str]:
    return set(EVIDENCE_ID_PATTERN.findall(text))


def verify_finding(
    report: dict[str, Any],
    available_evidence_ids: set[str],
) -> dict[str, Any]:
    """Check that report claims are grounded in evidence actually collected.

    A sentence counts as grounded when it either cites at least one known
    evidence id or is a generic recommendation (no factual assertion).
    """
    key_findings: list[str] = [str(f) for f in report.get("key_findings", [])]
    cited_ids = _extract_cited_ids(json.dumps(report))
    supported = cited_ids & available_evidence_ids
    hallucinated = cited_ids - available_evidence_ids

    grounded_sentences = 0
    total_finding_sentences = 0
    for finding in key_findings:
        for sentence in SENTENCE_SPLIT.split(finding):
            if not sentence.strip():
                continue
            total_finding_sentences += 1
            ids_in_sentence = _extract_cited_ids(sentence)
            if not ids_in_sentence or (ids_in_sentence & supported):
                grounded_sentences += 1

    technique = report.get("root_cause_technique")
    technique_supported = bool(technique and technique in available_evidence_ids)

    coverage = grounded_sentences / total_finding_sentences if total_finding_sentences else 0.0
    citation_precision = len(supported) / len(cited_ids) if cited_ids else 0.0
    confidence = round(0.5 * coverage + 0.5 * citation_precision, 4)

    verdicts: list[dict[str, Any]] = []
    for finding in key_findings:
        ids = _extract_cited_ids(finding)
        verdicts.append(
            {
                "claim": finding[:200],
                "grounded": bool(not ids or (ids & supported)),
                "citations": sorted(ids),
            }
        )

    return {
        "verdict": "supported"
        if hallucinated == set() and coverage >= 0.5
        else ("partially_supported" if hallucinated and coverage >= 0.5 else "unsupported")
        if key_findings
        else "no_claims",
        "confidence": confidence,
        "evidence_coverage": round(coverage, 3),
        "citation_precision": round(citation_precision, 3),
        "cited_evidence_count": len(supported),
        "hallucinated_citations": sorted(hallucinated)[:20],
        "technique_identified_supported": technique_supported,
        "claim_verdicts": verdicts,
    }
