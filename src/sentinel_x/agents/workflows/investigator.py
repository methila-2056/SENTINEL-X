"""ReAct-style autonomous investigation workflow with grounded verification."""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from sentinel_x.agents.tools.registry import Tool, ToolResult, build_default_tools
from sentinel_x.common.logging import get_logger
from sentinel_x.llm.client import OllamaClient
from sentinel_x.verification.verifier import verify_finding

logger = get_logger(__name__)

PLANNER_SYSTEM = """You are SENTINEL-X, an autonomous SOC incident investigator.
You investigate a correlated security incident by calling tools step by step.

Available tools:
{tool_docs}

Respond ONLY with JSON: {{"thought": "...", "tool": "<name>" or null,
"args": {{...}}, "done": false}}
Set "done": true when you have enough evidence to write the final report."""

REPORT_SYSTEM = """You are SENTINEL-X writing the final investigation report for a
security incident. Use ONLY facts supported by the evidence excerpts below.
Cite evidence by listing event ids or knowledge ids in "evidence_ids".
Structure: summary (2-3 sentences), root_cause_technique (MITRE id),
key_findings (list of strings), recommended_actions (list of strings),
evidence_ids (flat list). Respond ONLY with JSON."""


@dataclass
class InvestigationStep:
    step_index: int
    thought: str
    tool: str | None
    args: dict[str, Any]
    ok: bool
    duration_ms: int


@dataclass
class InvestigationReport:
    incident_id: str
    summary: str
    root_cause_technique: str | None
    key_findings: list[str]
    recommended_actions: list[str]
    evidence_ids: list[str]
    verification: dict[str, Any]
    steps: list[InvestigationStep] = field(default_factory=list)
    llm_calls: int = 0
    wall_time_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return data


class InvestigatorAgent:
    def __init__(
        self,
        client: OllamaClient | None = None,
        tools: dict[str, Tool] | None = None,
        max_steps: int = 8,
    ) -> None:
        self.client = client or OllamaClient()
        self.tools = tools if tools is not None else build_default_tools()
        self.max_steps = max_steps
        self._evidence_ids: set[str] = set()

    # ------------------------------------------------------------------ loop
    def investigate(self, incident_id: str) -> InvestigationReport:
        start = time.time()
        self._evidence_ids = set()
        transcript: list[dict[str, str]] = []
        steps: list[InvestigationStep] = []
        llm_calls = 0

        transcript.append(
            {
                "role": "user",
                "content": f"Investigate incident {incident_id}. Begin.",
            }
        )

        for step_index in range(self.max_steps):
            decision = self._next_action(transcript)
            llm_calls += 1
            tool_name = decision.get("tool")
            if decision.get("done") or not tool_name or tool_name not in self.tools:
                break
            args = decision.get("args") or {}
            step_start = time.perf_counter()
            result = self._execute(tool_name, args)
            duration_ms = int((time.perf_counter() - step_start) * 1000)
            steps.append(
                InvestigationStep(
                    step_index=step_index,
                    thought=str(decision.get("thought", ""))[:300],
                    tool=tool_name,
                    args=args,
                    ok=result.ok,
                    duration_ms=duration_ms,
                )
            )
            transcript.append(
                {
                    "role": "assistant",
                    "content": json.dumps(decision)[:800],
                }
            )
            transcript.append(
                {
                    "role": "user",
                    "content": f"TOOL_RESULT {tool_name}: {result.to_json()}",
                }
            )

        report_json = self._write_report(transcript, incident_id)
        llm_calls += 1
        verification = verify_finding(report_json, self._evidence_ids)

        return InvestigationReport(
            incident_id=incident_id,
            summary=report_json.get("summary", ""),
            root_cause_technique=report_json.get("root_cause_technique"),
            key_findings=list(report_json.get("key_findings", [])),
            recommended_actions=list(report_json.get("recommended_actions", [])),
            evidence_ids=list(report_json.get("evidence_ids", [])),
            verification=verification,
            steps=steps,
            llm_calls=llm_calls,
            wall_time_s=round(time.time() - start, 2),
        )

    # ------------------------------------------------------------- internals
    def _next_action(self, transcript: list[dict[str, str]]) -> dict[str, Any]:
        system = PLANNER_SYSTEM.format(tool_docs=self._tool_documentation())
        history = [{"role": m["role"], "content": m["content"][:2200]} for m in transcript[-6:]]
        response = self.client.generate(
            system + "\nConversation so far:",
            json.dumps(history[-2:] or [{"role": "user", "content": "begin"}]),
            json_mode=True,
            num_predict=512,
        )
        from sentinel_x.llm.client import _parse_json_object

        try:
            return _parse_json_object(response)
        except Exception:
            return {"done": True}

    def _execute(self, tool_name: str, args: dict[str, Any]) -> ToolResult:
        tool = self.tools[tool_name]
        try:
            payload = tool.fn(**args)
            result = ToolResult(
                tool=tool_name,
                args=args,
                ok=True,
                error=None
                if not isinstance(payload, dict) or "error" not in payload
                else payload["error"],
                payload=payload,
                evidence_ids=self._extract_evidence(payload),
            )
            self._evidence_ids.update(result.evidence_ids)
            logger.info("agent_tool_executed", tool=tool_name, ok=True)
            return result
        except TypeError as exc:
            return ToolResult(tool=tool_name, args=args, ok=False, error=f"bad args: {exc}")
        except Exception as exc:  # noqa: BLE001 - agent boundary
            logger.warning("agent_tool_failed", tool=tool_name, error=str(exc))
            return ToolResult(tool=tool_name, args=args, ok=False, error=str(exc))

    @staticmethod
    def _extract_evidence(payload: Any) -> list[str]:
        ids: list[str] = []

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                for key, value in node.items():
                    if key in ("event_id", "external_id", "entity_id", "id"):
                        if isinstance(value, str) and len(value) < 64:
                            ids.append(value)
                    else:
                        walk(value)
            elif isinstance(node, list):
                for item in node[:50]:
                    walk(item)

        walk(payload)
        return ids[:100]

    def _tool_documentation(self) -> str:
        lines = []
        for tool in self.tools.values():
            params = ", ".join(f"{k}:{v}" for k, v in tool.parameters.items())
            lines.append(f"- {tool.name}({params}): {tool.description}")
        return "\n".join(lines)

    def _write_report(self, transcript: list[dict[str, str]], incident_id: str) -> dict[str, Any]:
        evidence_digest = "\n".join(m["content"][:800] for m in transcript if m["role"] == "user")
        prompt = f"Incident: {incident_id}\n\nEvidence collected:\n{evidence_digest[:6000]}"
        try:
            raw = self.client.generate(REPORT_SYSTEM, prompt, json_mode=True, num_predict=900)
            from sentinel_x.llm.client import _parse_json_object

            return _parse_json_object(raw)
        except Exception as exc:
            logger.warning("report_generation_failed", error=str(exc))
            return {
                "summary": "Investigation completed but report generation failed.",
                "root_cause_technique": None,
                "key_findings": [],
                "recommended_actions": [],
                "evidence_ids": sorted(self._evidence_ids)[:20],
            }
