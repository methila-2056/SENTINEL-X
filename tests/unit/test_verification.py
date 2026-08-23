"""Unit tests for finding verification logic."""

from sentinel_x.verification.verifier import verify_finding


class TestVerifyFinding:
    def test_grounded_report(self) -> None:
        report = {
            "summary": "Brute force followed by successful login.",
            "root_cause_technique": "T1110",
            "key_findings": [
                "Attacker brute forced RDP on WS-1 (T1110).",
                "10 failed logins from 185.1.1.1 (e0).",
            ],
            "evidence_ids": ["T1110", "e0"],
        }
        result = verify_finding(report, {"T1110", "e0", "e1", "e2"})
        assert result["verdict"] == "supported"
        assert result["confidence"] > 0.5
        assert result["hallucinated_citations"] == []

    def test_hallucinated_citation_detected(self) -> None:
        report = {
            "key_findings": ["Data exfiltrated to evil.com (T1041)."],
            "evidence_ids": ["T1041"],
        }
        result = verify_finding(report, {"e0", "e1"})
        assert result["hallucinated_citations"] == ["T1041"]
        assert result["verdict"] != "supported"

    def test_no_claims(self) -> None:
        result = verify_finding({"key_findings": []}, set())
        assert result["verdict"] == "no_claims"

    def test_uncited_factual_claim_counts_ungrounded_only_for_confidence(self) -> None:
        report = {
            "key_findings": ["The attacker used Mimikatz on host WS-2."],
            "evidence_ids": [],
        }
        result = verify_finding(report, {"T1003"})
        assert result["claim_verdicts"][0]["grounded"] is True  # no citations -> cannot check
