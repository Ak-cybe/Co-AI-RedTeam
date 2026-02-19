"""
Validator Agent — Pre-execution safety and syntax validation.

Implements Co-RedTeam §3.3: Before execution, each proposed action is
passed through a Validation agent to ensure commands are well-formed,
syntactically sound, and aligned with the intended goal.

This validation step is critical in security settings to prevent
unintended damage or accidental scope violations.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel

from co_redteam.agents.base import AgentRole, BaseAgent
from co_redteam.config import LLMConfig


class ValidationResult(BaseModel):
    """Result of pre-execution command validation."""

    is_valid: bool
    is_safe: bool
    explanation: str
    sanitized_command: str = ""
    risk_level: str = "low"
    scope_violations: list[str] = []
    suggestions: list[str] = []


VALIDATOR_SYSTEM_PROMPT = """You are a security command validator. Before any command is executed in a sandboxed environment, you MUST verify:

1. **Syntax**: Is the command syntactically correct (valid bash/python)?
2. **Safety**: Does the command avoid destructive operations outside the sandbox?
   - No `rm -rf /`, no disk-wiping, no fork bombs
   - No network exfiltration to external hosts (only localhost/target allowed)
   - No credential harvesting beyond the assessment scope
3. **Scope Alignment**: Does the command match the stated exploitation goal?
4. **Well-Formedness**: Are paths, variables, and arguments properly quoted/escaped?

RED FLAGS (mark as invalid):
- Commands targeting host filesystems outside /workspace
- Attempts to escape the Docker sandbox
- Denial-of-service payloads against production systems
- Data exfiltration to external servers

OUTPUT FORMAT: JSON with:
- is_valid (bool): command passes all checks
- is_safe (bool): no safety concerns
- explanation (string): reasoning
- sanitized_command (string): cleaned version if minor fixes needed, empty if invalid
- risk_level (string): "low", "medium", "high", "critical"
- scope_violations (array of strings): any scope issues found
- suggestions (array of strings): improvements"""


class ValidatorAgent(BaseAgent):
    """
    Pre-execution validation agent.

    Checks commands for syntax correctness, safety constraints,
    and goal alignment before they reach the Executor.
    """

    def __init__(self, llm_config: LLMConfig) -> None:
        super().__init__(
            role=AgentRole.VALIDATOR,
            llm_config=llm_config,
            system_prompt=VALIDATOR_SYSTEM_PROMPT,
        )

    async def validate_command(
        self,
        command: str,
        goal: str,
        exploit_context: str = "",
    ) -> ValidationResult:
        """
        Validate a command before execution.

        Args:
            command: The bash/python command to validate.
            goal: What the command is supposed to achieve.
            exploit_context: Broader exploitation context (CWE, target).

        Returns:
            ValidationResult with safety assessment.
        """
        prompt = (
            f"## Command to Validate\n```\n{command}\n```\n\n"
            f"## Intended Goal\n{goal}\n\n"
        )

        if exploit_context:
            prompt += f"## Exploit Context\n{exploit_context}\n\n"

        prompt += "## Task\nValidate this command. Return JSON."

        response = await self.invoke(prompt)

        if not response.success:
            return ValidationResult(
                is_valid=False,
                is_safe=False,
                explanation=f"Validation failed: {response.error}",
                risk_level="high",
            )

        return self._parse_response(response.content, command)

    def _parse_response(self, content: str, original_command: str) -> ValidationResult:
        """Parse validation response."""
        try:
            json_str = content
            if "```json" in content:
                json_str = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                json_str = content.split("```")[1].split("```")[0]

            raw = json.loads(json_str)

            return ValidationResult(
                is_valid=bool(raw.get("is_valid", False)),
                is_safe=bool(raw.get("is_safe", False)),
                explanation=raw.get("explanation", ""),
                sanitized_command=raw.get("sanitized_command", original_command),
                risk_level=raw.get("risk_level", "medium"),
                scope_violations=raw.get("scope_violations", []),
                suggestions=raw.get("suggestions", []),
            )

        except (json.JSONDecodeError, IndexError):
            return ValidationResult(
                is_valid=False,
                is_safe=False,
                explanation="Failed to parse validation response",
                risk_level="high",
            )

    async def _reason(
        self,
        prompt: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute LLM reasoning for validation."""
        return await self._call_llm(prompt, temperature=0.0)
