"""Tests for the agent evaluation harness scoring logic (no LLM required)."""

from sentinel_x.agents.workflows.investigator import InvestigationReport, InvestigationStep
from sentinel_x.evaluation.agents.harness import AgentScenario, _score_report


def _report(**overrides) -> InvestigationReport:
    base = dict(
        incident_id="det-0001",
        summary="Brute force followed by suspicious process execution.",
        root_cause_technique="T1110",
        key_findings=["Multiple failed logins (T1110)."],
        recommended_actions=["Reset credentials."],
        evidence_ids=["ev-1", "T1110"],
        verification={
            "verdict": "supported",
            "confidence": 0.9,
            "evidence_coverage": 1.0,
            "citation_precision": 1.0,
        },
        steps=[
            InvestigationStep(0, "look up incident", "get_incident", {}, True, 10),
            InvestigationStep(
                1, "search intel", "search_threat_intelligence", {"query": "brute force"}, True, 20
            ),
        ],
        llm_calls=3,
        wall_time_s=12.5,
    )
    base.update(overrides)
    return InvestigationReport(**base)


class TestScoreReport:
    def test_success_case(self):
        scenario = AgentScenario(
            incident_id="det-0001",
            expected_technique_ids=["T1110", "T1110.003"],
            scenario_type="brute_force",
        )
        result = _score_report(scenario, _report(), {"prompt_tokens": 100, "completion_tokens": 50})
        assert result.task_completed
        assert result.technique_correct
        assert result.verification_supported
        assert result.tool_success_rate == 1.0

    def test_wrong_technique_fails(self):
        scenario = AgentScenario("det-0001", expected_technique_ids=["T1486"])
        result = _score_report(scenario, _report(), {})
        assert not result.technique_correct

    def test_failed_generation_not_completed(self):
        report = _report(summary="Investigation completed but report generation failed.")
        result = _score_report(AgentScenario("det-0001"), report, {})
        assert not result.task_completed

    def test_unsupported_verdict(self):
        report = _report(
            verification={"verdict": "unsupported", "confidence": 0.2, "evidence_coverage": 0.0}
        )
        result = _score_report(AgentScenario("det-0001", ["T1110"]), report, {})
        assert not result.verification_supported

    def test_tool_failures_lower_rate(self):
        report = _report(
            steps=[
                InvestigationStep(0, "ok call", "get_incident", {}, True, 5),
                InvestigationStep(1, "bad args", "query_events", {}, False, 5),
            ]
        )
        result = _score_report(AgentScenario("det-0001"), report, {})
        assert result.tool_success_rate == 0.5
