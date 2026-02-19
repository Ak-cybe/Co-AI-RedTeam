"""
Planner Agent — Creates and maintains exploit plans.

Implements Co-RedTeam Stage II planning with explicit,
revisable exploit strategies and feedback-driven refinement.
"""

from __future__ import annotations

import json
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from co_redteam.agents.base import AgentRole, BaseAgent
from co_redteam.config import LLMConfig


class StepStatus(str, Enum):
    """Status of an exploit plan step."""

    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    DONE = "done"
    BLOCKED = "blocked"
    SKIPPED = "skipped"


class ExploitStep(BaseModel):
    """Single step in an exploit plan."""

    step_id: int
    goal: str
    action: str
    command: str = ""
    status: StepStatus = StepStatus.PLANNED
    depends_on: int | None = None
    failure_reason: str = ""
    output: str = ""


class ExploitPlan(BaseModel):
    """Complete exploit plan for a vulnerability."""

    vulnerability_id: str
    target_cwe: str
    objective: str
    steps: list[ExploitStep] = Field(default_factory=list)
    current_step_index: int = 0
    iteration_count: int = 0
    max_iterations: int = 20

    @property
    def current_step(self) -> ExploitStep | None:
        """Return the current step to execute."""
        if self.current_step_index < len(self.steps):
            return self.steps[self.current_step_index]
        return None

    @property
    def is_complete(self) -> bool:
        """Check if all steps are done or skipped."""
        return all(s.status in (StepStatus.DONE, StepStatus.SKIPPED) for s in self.steps)

    @property
    def has_budget(self) -> bool:
        """Check if iteration budget allows more attempts."""
        return self.iteration_count < self.max_iterations

    def advance(self) -> None:
        """Move to the next planned step, or signal completion."""
        for idx in range(self.current_step_index + 1, len(self.steps)):
            if self.steps[idx].status == StepStatus.PLANNED:
                self.current_step_index = idx
                return
        # No more planned steps — move index beyond bounds so current_step returns None
        self.current_step_index = len(self.steps)

    def mark_done(self, step_id: int, output: str = "") -> None:
        """Mark a step as successfully completed."""
        for step in self.steps:
            if step.step_id == step_id:
                step.status = StepStatus.DONE
                step.output = output
                break
        self.advance()

    def mark_blocked(self, step_id: int, reason: str) -> None:
        """Mark a step as blocked with failure reason."""
        for step in self.steps:
            if step.step_id == step_id:
                step.status = StepStatus.BLOCKED
                step.failure_reason = reason
                break

    def insert_corrective_step(self, after_step_id: int, new_step: ExploitStep) -> None:
        """Insert a corrective step after a blocked step."""
        insert_idx = 0
        for idx, step in enumerate(self.steps):
            if step.step_id == after_step_id:
                insert_idx = idx + 1
                break
        self.steps.insert(insert_idx, new_step)


PLANNER_SYSTEM_PROMPT = """You are an expert exploit planner. Given a vulnerability description and codebase context, create a step-by-step exploit plan.

PLANNING PRINCIPLES:
1. **Grounding**: Before planning, understand the target stack, attack surface, and prerequisites.
2. **Explicit Steps**: Each step specifies a goal, action, and executable command.
3. **Revisable**: Plans can be updated based on execution feedback.
4. **Progressive**: Start with reconnaissance, then confirm vulnerability, then full exploitation.

OUTPUT FORMAT: JSON object with:
- vulnerability_id: string
- target_cwe: string
- objective: string
- steps: array of {step_id, goal, action, command, status: "planned", depends_on}

Generate concrete, executable commands (bash/python) for each step.
Commands run in an isolated Docker sandbox."""


class PlannerAgent(BaseAgent):
    """
    Exploit planning agent.

    Creates and maintains explicit, revisable exploit plans with
    concrete executable steps and feedback-driven refinement.
    """

    def __init__(self, llm_config: LLMConfig) -> None:
        super().__init__(
            role=AgentRole.PLANNER,
            llm_config=llm_config,
            system_prompt=PLANNER_SYSTEM_PROMPT,
        )

    async def create_plan(
        self,
        vulnerability_description: str,
        code_context: str = "",
        memory_hints: list[str] | None = None,
    ) -> ExploitPlan:
        """
        Create an initial exploit plan for a vulnerability.

        Args:
            vulnerability_description: Vulnerability details and evidence chain.
            code_context: Relevant source code.
            memory_hints: Prior successful strategies from memory.

        Returns:
            ExploitPlan with step-by-step exploitation strategy.
        """
        prompt = self._build_plan_prompt(vulnerability_description, code_context, memory_hints)
        response = await self.invoke(prompt)

        if not response.success:
            return ExploitPlan(
                vulnerability_id="unknown",
                target_cwe="unknown",
                objective="Failed to generate plan",
            )

        return self._parse_plan(response.content)

    async def revise_plan(
        self,
        current_plan: ExploitPlan,
        execution_feedback: str,
        evaluation_notes: str,
    ) -> ExploitPlan:
        """
        Revise the exploit plan based on execution feedback.

        Args:
            current_plan: The existing plan with step statuses.
            execution_feedback: Raw output from the last execution.
            evaluation_notes: Assessment from the Evaluation Agent.

        Returns:
            Updated ExploitPlan with revisions applied.
        """
        prompt = (
            f"## Current Exploit Plan\n```json\n"
            f"{current_plan.model_dump_json(indent=2)}\n```\n\n"
            f"## Last Execution Output\n```\n{execution_feedback}\n```\n\n"
            f"## Evaluation Notes\n{evaluation_notes}\n\n"
            f"## Task\n"
            f"Revise the plan based on this feedback.\n"
            f"- Update blocked steps with failure reasons\n"
            f"- Insert corrective steps if needed\n"
            f"- Reassess downstream steps\n"
            f"- Generate the next executable command\n"
            f"Return the FULL updated plan as JSON."
        )

        response = await self.invoke(prompt)
        if not response.success:
            return current_plan

        revised = self._parse_plan(response.content)
        revised.iteration_count = current_plan.iteration_count + 1
        revised.max_iterations = current_plan.max_iterations
        return revised

    async def generate_action(self, plan: ExploitPlan) -> str | None:
        """Generate the next executable command from the plan."""
        current = plan.current_step
        if not current:
            return None

        prompt = (
            f"Generate a concrete, executable command for this exploit step:\n\n"
            f"Goal: {current.goal}\n"
            f"Action: {current.action}\n"
            f"Context: Targeting {plan.target_cwe} — {plan.objective}\n\n"
            f"Return ONLY the executable command (bash or python script)."
        )

        response = await self.invoke(prompt)
        if response.success:
            return response.content.strip()
        return None

    def _build_plan_prompt(
        self,
        vulnerability_description: str,
        code_context: str,
        memory_hints: list[str] | None,
    ) -> str:
        """Build the initial planning prompt."""
        parts = [
            f"## Vulnerability Details\n{vulnerability_description}\n",
        ]

        if code_context:
            parts.append(f"## Code Context\n```\n{code_context}\n```\n")

        if memory_hints:
            hints = "\n".join(f"- {h}" for h in memory_hints)
            parts.append(f"## Prior Strategies\n{hints}\n")

        parts.append(
            "\n## Task\n"
            "Create a step-by-step exploit plan.\n"
            "Include 4-8 concrete steps from reconnaissance to PoC generation.\n"
            "Each step MUST have an executable command.\n"
            "Return as JSON."
        )

        return "\n".join(parts)

    def _parse_plan(self, content: str) -> ExploitPlan:
        """Parse LLM response into an ExploitPlan."""
        try:
            json_str = content
            if "```json" in content:
                json_str = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                json_str = content.split("```")[1].split("```")[0]

            raw = json.loads(json_str)

            steps = []
            for step_data in raw.get("steps", []):
                steps.append(
                    ExploitStep(
                        step_id=int(step_data.get("step_id", len(steps) + 1)),
                        goal=step_data.get("goal", ""),
                        action=step_data.get("action", ""),
                        command=step_data.get("command", ""),
                        status=StepStatus.PLANNED,
                        depends_on=step_data.get("depends_on"),
                    )
                )

            return ExploitPlan(
                vulnerability_id=raw.get("vulnerability_id", "unknown"),
                target_cwe=raw.get("target_cwe", "unknown"),
                objective=raw.get("objective", ""),
                steps=steps,
            )

        except (json.JSONDecodeError, IndexError, KeyError):
            return ExploitPlan(
                vulnerability_id="unknown",
                target_cwe="unknown",
                objective="Failed to parse plan",
            )

    async def _reason(
        self,
        prompt: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute LLM reasoning for planning."""
        return await self._call_llm(prompt, temperature=0.2)
