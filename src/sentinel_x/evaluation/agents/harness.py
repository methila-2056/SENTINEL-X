"""Agent evaluation harness: scenario-based scoring of investigations.

Metrics per scenario:
  - task_completed        : investigation produced a non-empty report
  - technique_correct     : root_cause_technique matches ground truth
  - verification_supported: claim verifier verdict is 'supported'
  - tool_success_rate     : share of tool calls that executed without error
  - evidence_coverage     : verifier's grounded-sentence coverage
  - latency_s, llm_calls, tokens

Aggregate: success_rate = scenarios where technique_correct AND
verification_supported (and report produced).
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field

import numpy as np

from sentinel_x.agents.workflows.investigator import InvestigationReport, InvestigatorAgent
from sentinel_x.common.logging import get_logger

logger = get_logger(__name__)


@dataclass
class AgentScenario:
    incident_id: str
    expected_technique_ids: list[str] = field(default_factory=list)
    scenario_type: str = "unknown"
    description: str = ""


@dataclass
class ScenarioResult:
    incident_id: str
    scenario_type: str
    task_completed: bool
    technique_correct: bool
    predicted_technique: str | None
    expected_techniques: list[str]
    verification_supported: bool
    verification_confidence: float
    evidence_coverage: float
    n_tool_calls: int
    tool_success_rate: float
    llm_calls: int
    wall_time_s: float
    prompt_tokens: int
    completion_tokens: int


def _score_report(
    scenario: AgentScenario, report: InvestigationReport, usage: dict[str, int]
) -> ScenarioResult:
    completed = bool(report.summary) and not report.summary.startswith(
        "Investigation completed but report generation failed"
    )
    predicted = report.root_cause_technique
    expected = set(scenario.expected_technique_ids)
    technique_correct = bool(predicted and predicted in expected)

    verification = report.verification or {}
    supported = verification.get("verdict") == "supported"

    ok_steps = [s for s in report.steps if s.ok]
    tool_rate = len(ok_steps) / len(report.steps) if report.steps else 0.0

    return ScenarioResult(
        incident_id=scenario.incident_id,
        scenario_type=scenario.scenario_type,
        task_completed=completed,
        technique_correct=technique_correct,
        predicted_technique=predicted,
        expected_techniques=sorted(expected),
        verification_supported=supported,
        verification_confidence=float(verification.get("confidence", 0.0)),
        evidence_coverage=float(verification.get("evidence_coverage", 0.0)),
        n_tool_calls=len(report.steps),
        tool_success_rate=round(tool_rate, 3),
        llm_calls=report.llm_calls,
        wall_time_s=report.wall_time_s,
        prompt_tokens=int(usage.get("prompt_tokens", 0)),
        completion_tokens=int(usage.get("completion_tokens", 0)),
    )


def evaluate_agent(
    scenarios: list[AgentScenario],
    agent: InvestigatorAgent | None = None,
) -> dict:
    """Run every scenario through the investigator and aggregate results."""
    agent = agent or InvestigatorAgent(max_steps=6)
    results: list[ScenarioResult] = []

    for scenario in scenarios:
        start = time.time()
        try:
            report = agent.investigate(scenario.incident_id)
            # accumulate token usage across the agent's LLM calls
            usage = {
                "prompt_tokens": getattr(agent.client, "last_usage", {}).get("prompt_tokens", 0)
                * max(report.llm_calls, 1),
                "completion_tokens": getattr(agent.client, "last_usage", {}).get(
                    "completion_tokens", 0
                )
                * max(report.llm_calls, 1),
            }
            result = _score_report(scenario, report, usage)
        except Exception as exc:  # noqa: BLE001 - evaluation boundary
            logger.warning(
                "agent_eval_scenario_failed", incident=scenario.incident_id, error=str(exc)
            )
            result = ScenarioResult(
                incident_id=scenario.incident_id,
                scenario_type=scenario.scenario_type,
                task_completed=False,
                technique_correct=False,
                predicted_technique=None,
                expected_techniques=sorted(scenario.expected_technique_ids),
                verification_supported=False,
                verification_confidence=0.0,
                evidence_coverage=0.0,
                n_tool_calls=0,
                tool_success_rate=0.0,
                llm_calls=0,
                wall_time_s=round(time.time() - start, 2),
                prompt_tokens=0,
                completion_tokens=0,
            )
        results.append(result)
        logger.info(
            "agent_eval_scenario_done",
            incident=result.incident_id,
            success=result.technique_correct and result.verification_supported,
        )

    successes = [
        r for r in results if r.task_completed and r.technique_correct and r.verification_supported
    ]
    summary = {
        "n_scenarios": len(results),
        "task_completion_rate": round(np.mean([r.task_completed for r in results]), 4)
        if results
        else 0.0,
        "technique_accuracy": round(np.mean([r.technique_correct for r in results]), 4)
        if results
        else 0.0,
        "verification_supported_rate": round(
            np.mean([r.verification_supported for r in results]), 4
        )
        if results
        else 0.0,
        "success_rate": round(len(successes) / len(results), 4) if results else 0.0,
        "avg_tool_success_rate": round(float(np.mean([r.tool_success_rate for r in results])), 4)
        if results
        else 0.0,
        "avg_wall_time_s": round(float(np.mean([r.wall_time_s for r in results])), 2)
        if results
        else 0.0,
        "avg_llm_calls": round(float(np.mean([r.llm_calls for r in results])), 2)
        if results
        else 0.0,
        "total_prompt_tokens": sum(r.prompt_tokens for r in results),
        "total_completion_tokens": sum(r.completion_tokens for r in results),
    }
    return {"summary": summary, "results": [asdict(r) for r in results]}
