"""
Critique Agent — Validates and refines vulnerability hypotheses.

Acts as an independent verifier, evaluating evidence quality,
assessing false positive risk, and assigning risk levels.
"""

from __future__ import annotations

import json
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from co_redteam.agents.analysis import VulnerabilityDraft
from co_redteam.agents.base import AgentRole, BaseAgent
from co_redteam.config import LLMConfig


class ReviewStatus(str, Enum):
    """Review status assigned by the Critique Agent."""

    APPROVED = "approved"
    REJECTED = "rejected"
    NEEDS_REFINEMENT = "needs_refinement"


class CritiqueResult(BaseModel):
    """Critique assessment for a single vulnerability draft."""

    vulnerability_id: str
    status: ReviewStatus
    risk_level: str
    reasoning: str
    feedback: str = ""
    suggestions: list[str] = Field(default_factory=list)
    adjusted_confidence: float = Field(ge=0.0, le=1.0)


CRITIQUE_SYSTEM_PROMPT = """You are a senior security reviewer acting as an independent verifier for vulnerability reports. Your role is to CRITICALLY evaluate each vulnerability hypothesis.

For EACH vulnerability, assess:

1. **Evidence Quality**: Is the data flow chain complete and verifiable in the code?
   - Source clearly identified with file:line?
   - Sink clearly identified with file:line?
   - Every intermediate step documented?

2. **False Positive Risk**: Could this be a false alarm?
   - Is the input validated upstream?
   - Does the framework provide built-in protection?
   - Are there WAF/middleware guards?

3. **Impact Assessment**: What's the realistic damage?
   - Can an external attacker trigger this?
   - What data/systems are at risk?

4. **Exploitability**: How difficult is exploitation?
   - Are there prerequisites (auth, config, network access)?
   - Is the vulnerable code reachable?

RISK LEVELS:
- Critical: RCE, auth bypass, data exfiltration — no mitigating controls
- High: SQLi, XSS, SSRF — exploitable with moderate effort
- Medium: Info disclosure, weak crypto — specific conditions needed
- Low: Missing headers, verbose errors — limited direct impact

REVIEW STATUSES:
- approved: Strong evidence, clear impact
- rejected: Insufficient evidence, mitigating controls exist
- needs_refinement: Plausible but under-supported

OUTPUT FORMAT: JSON array of critique objects with:
- vulnerability_id, status, risk_level, reasoning, feedback, adjusted_confidence"""


class CritiqueAgent(BaseAgent):
    """
    Vulnerability critique and refinement agent.

    Reviews vulnerability drafts from the Analysis Agent,
    validates evidence chains, and filters false positives.
    """

    def __init__(self, llm_config: LLMConfig) -> None:
        super().__init__(
            role=AgentRole.CRITIQUE,
            llm_config=llm_config,
            system_prompt=CRITIQUE_SYSTEM_PROMPT,
        )

    async def review_vulnerabilities(
        self,
        drafts: list[VulnerabilityDraft],
        code_context: str = "",
    ) -> list[CritiqueResult]:
        """
        Review vulnerability drafts and provide critique.

        Args:
            drafts: Vulnerability hypotheses from the Analysis Agent.
            code_context: Relevant source code for verification.

        Returns:
            List of critique results with review status.
        """
        if not drafts:
            return []

        prompt = self._build_critique_prompt(drafts, code_context)
        response = await self.invoke(prompt)

        if not response.success:
            return []

        return self._parse_response(response.content, drafts)

    def _build_critique_prompt(
        self,
        drafts: list[VulnerabilityDraft],
        code_context: str,
    ) -> str:
        """Build critique prompt with vulnerability drafts."""
        vulns_json = json.dumps([d.model_dump() for d in drafts], indent=2)

        parts = [
            "## Vulnerability Drafts to Review\n",
            f"```json\n{vulns_json}\n```\n",
        ]

        if code_context:
            parts.append(f"\n## Relevant Code Context\n```\n{code_context}\n```\n")

        parts.append(
            "\n## Task\n"
            "Critically review each vulnerability draft.\n"
            "For each: verify evidence, check for false positives, assess exploitability.\n"
            "Return JSON array of critique objects."
        )

        return "\n".join(parts)

    def _parse_response(
        self,
        content: str,
        original_drafts: list[VulnerabilityDraft],
    ) -> list[CritiqueResult]:
        """Parse critique response into structured results."""
        try:
            json_str = content
            if "```json" in content:
                json_str = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                json_str = content.split("```")[1].split("```")[0]

            raw_results = json.loads(json_str)
            if not isinstance(raw_results, list):
                raw_results = [raw_results]

            critiques = []
            for raw in raw_results:
                try:
                    status_str = raw.get("status", "needs_refinement").lower()
                    status = ReviewStatus(status_str)
                except ValueError:
                    status = ReviewStatus.NEEDS_REFINEMENT

                critiques.append(
                    CritiqueResult(
                        vulnerability_id=raw.get("vulnerability_id", ""),
                        status=status,
                        risk_level=raw.get("risk_level", "Medium"),
                        reasoning=raw.get("reasoning", ""),
                        feedback=raw.get("feedback", ""),
                        suggestions=raw.get("suggestions", []),
                        adjusted_confidence=float(raw.get("adjusted_confidence", 0.5)),
                    )
                )

            return critiques

        except (json.JSONDecodeError, IndexError):
            # If parsing fails, mark all as needs_refinement
            return [
                CritiqueResult(
                    vulnerability_id=d.vulnerability_id,
                    status=ReviewStatus.NEEDS_REFINEMENT,
                    risk_level=d.severity,
                    reasoning="Failed to parse critique response",
                    adjusted_confidence=d.confidence * 0.8,
                )
                for d in original_drafts
            ]

    async def _reason(
        self,
        prompt: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute LLM reasoning for critique."""
        return await self._call_llm(prompt, temperature=0.05)
