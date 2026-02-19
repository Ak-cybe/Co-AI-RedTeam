"""
Evaluator Agent — Assesses execution outcomes and generates feedback.

Converts low-level execution traces into high-level reasoning signals
for the Planner's next iteration.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel

from co_redteam.agents.base import AgentRole, BaseAgent
from co_redteam.agents.executor import ExecutionResult
from co_redteam.config import LLMConfig


class EvaluationResult(BaseModel):
    """Assessment of an execution attempt."""

    goal_achieved: bool
    explanation: str
    deviations: list[str]
    suggestions: list[str]
    should_continue: bool
    confidence: float


EVALUATOR_SYSTEM_PROMPT = """You are a security execution evaluator. Given an execution goal and its output (stdout, stderr, exit code), determine:

1. **Goal Achievement**: Did the execution achieve its intended goal?
2. **Deviations**: What unexpected behaviors occurred?
3. **Root Cause**: If failed, why? (wrong path, missing dep, WAF, auth required, etc.)
4. **Next Steps**: Concrete suggestions for the planner.
5. **Continue/Stop**: Should we keep trying or is this vector exhausted?

OUTPUT FORMAT: JSON with:
- goal_achieved (bool)
- explanation (string)
- deviations (array of strings)
- suggestions (array of strings)
- should_continue (bool)
- confidence (0.0-1.0)

Be precise and actionable. The planner will use your feedback to revise the exploit plan."""


class EvaluatorAgent(BaseAgent):
    """
    Execution evaluation agent.

    Interprets execution results and generates actionable feedback
    for the Planner to refine the exploit plan.
    """

    def __init__(self, llm_config: LLMConfig) -> None:
        super().__init__(
            role=AgentRole.EVALUATOR,
            llm_config=llm_config,
            system_prompt=EVALUATOR_SYSTEM_PROMPT,
        )

    async def evaluate(
        self,
        goal: str,
        execution_result: ExecutionResult,
        plan_context: str = "",
    ) -> EvaluationResult:
        """
        Evaluate an execution result against its intended goal.

        Args:
            goal: What the execution was supposed to achieve.
            execution_result: Raw execution output.
            plan_context: Broader exploit plan context.

        Returns:
            Structured evaluation with feedback and suggestions.
        """
        prompt = (
            f"## Execution Goal\n{goal}\n\n"
            f"## Execution Result\n"
            f"- Exit Code: {execution_result.exit_code}\n"
            f"- Timed Out: {execution_result.timed_out}\n"
            f"- Duration: {execution_result.duration_ms:.0f}ms\n\n"
            f"### STDOUT\n```\n{execution_result.stdout[:3000]}\n```\n\n"
            f"### STDERR\n```\n{execution_result.stderr[:2000]}\n```\n\n"
        )

        if plan_context:
            prompt += f"## Plan Context\n{plan_context}\n\n"

        prompt += "## Task\nEvaluate this execution. Return JSON."

        response = await self.invoke(prompt)

        if not response.success:
            return EvaluationResult(
                goal_achieved=False,
                explanation=f"Evaluation failed: {response.error}",
                deviations=[],
                suggestions=["Retry execution"],
                should_continue=True,
                confidence=0.3,
            )

        return self._parse_response(response.content)

    def _parse_response(self, content: str) -> EvaluationResult:
        """Parse evaluation response."""
        try:
            json_str = content
            if "```json" in content:
                json_str = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                json_str = content.split("```")[1].split("```")[0]

            raw = json.loads(json_str)

            return EvaluationResult(
                goal_achieved=bool(raw.get("goal_achieved", False)),
                explanation=raw.get("explanation", ""),
                deviations=raw.get("deviations", []),
                suggestions=raw.get("suggestions", []),
                should_continue=bool(raw.get("should_continue", True)),
                confidence=float(raw.get("confidence", 0.5)),
            )

        except (json.JSONDecodeError, IndexError):
            return EvaluationResult(
                goal_achieved=False,
                explanation="Failed to parse evaluation response",
                deviations=[],
                suggestions=["Check execution environment"],
                should_continue=True,
                confidence=0.3,
            )

    async def _reason(
        self,
        prompt: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute LLM reasoning for evaluation."""
        return await self._call_llm(prompt, temperature=0.1)
