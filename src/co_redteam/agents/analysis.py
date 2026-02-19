"""
Analysis Agent — Vulnerability discovery through code-aware reasoning.

Implements Co-RedTeam Stage I: evidence-grounded vulnerability hypothesis generation.
Equipped with code-browsing tools and CWE/OWASP knowledge base.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field

from co_redteam.agents.base import AgentRole, BaseAgent
from co_redteam.config import LLMConfig


class VulnerabilityDraft(BaseModel):
    """Structured vulnerability hypothesis from the Analysis Agent."""

    vulnerability_id: str
    cwe_class: str
    severity: str
    title: str
    description: str
    source_file: str
    source_line: int
    source_input_type: str
    sink_file: str
    sink_line: int
    sink_operation: str
    data_flow: list[str]
    missing_guard: str
    exploit_hypothesis: str
    confidence: float = Field(ge=0.0, le=1.0)


class DiscoveryResult(BaseModel):
    """Output of the vulnerability discovery stage."""

    vulnerabilities: list[VulnerabilityDraft] = Field(default_factory=list)
    files_analyzed: int = 0
    total_candidates: int = 0
    approved_count: int = 0
    rejected_count: int = 0


ANALYSIS_SYSTEM_PROMPT = """You are an expert security analyst performing vulnerability discovery on a software codebase. Your task is to systematically identify security vulnerabilities by:

1. **Code Exploration**: Inspect file hierarchies, entry points, configuration files, and code logic.
2. **Data Flow Analysis**: Trace how untrusted inputs propagate through the program to sensitive sinks.
3. **CWE/OWASP Grounding**: Map suspicious patterns to known vulnerability classes (CWE-89, CWE-79, CWE-78, CWE-918, CWE-22, CWE-502, CWE-287, CWE-798, CWE-1336, etc.).
4. **Evidence Chain Construction**: For each candidate, build a rigorous evidence chain:
   - Input source (where untrusted data enters)
   - Vulnerable sink (where data reaches sensitive operations)
   - Missing guards (what validation/sanitization is absent)
   - Data flow path (step-by-step from source to sink)
   - Exploit hypothesis (how it could be exploited)

OUTPUT FORMAT: Return a JSON array of vulnerability objects. Each must have:
- vulnerability_id: "VULN-NNN"
- cwe_class: "CWE-XXX: Name"
- severity: "Critical" | "High" | "Medium" | "Low"
- title: Short vulnerability title
- description: Detailed description
- source_file, source_line, source_input_type: Where input enters
- sink_file, sink_line, sink_operation: Where input reaches danger
- data_flow: Array of flow steps
- missing_guard: What protection is missing
- exploit_hypothesis: How to exploit
- confidence: 0.0-1.0

Focus on HIGH-IMPACT vulnerabilities. Avoid false positives — every finding must have CONCRETE evidence from the actual code."""


class AnalysisAgent(BaseAgent):
    """
    Vulnerability discovery agent.

    Performs deep code analysis grounded in security domain knowledge
    to generate evidence-backed vulnerability hypotheses.
    """

    def __init__(self, llm_config: LLMConfig) -> None:
        super().__init__(
            role=AgentRole.ANALYSIS,
            llm_config=llm_config,
            system_prompt=ANALYSIS_SYSTEM_PROMPT,
        )

    async def analyze_codebase(
        self,
        code_context: str,
        file_tree: str,
        tech_stack: str,
        memory_hints: list[str] | None = None,
    ) -> DiscoveryResult:
        """
        Analyze a codebase for vulnerabilities.

        Args:
            code_context: Concatenated source code of target files.
            file_tree: File/directory structure of the project.
            tech_stack: Detected technology stack description.
            memory_hints: Optional prior vulnerability patterns from memory.

        Returns:
            DiscoveryResult with vulnerability drafts.
        """
        prompt = self._build_analysis_prompt(code_context, file_tree, tech_stack, memory_hints)
        response = await self.invoke(prompt)

        if not response.success:
            return DiscoveryResult()

        return self._parse_response(response.content)

    def _build_analysis_prompt(
        self,
        code_context: str,
        file_tree: str,
        tech_stack: str,
        memory_hints: list[str] | None = None,
    ) -> str:
        """Build the analysis prompt with all context."""
        parts = [
            f"## Target Codebase\n\n### Technology Stack\n{tech_stack}\n",
            f"### File Structure\n```\n{file_tree}\n```\n",
            f"### Source Code\n```\n{code_context}\n```\n",
        ]

        if memory_hints:
            hints_text = "\n".join(f"- {h}" for h in memory_hints)
            parts.append(f"\n### Prior Vulnerability Patterns (from memory)\n{hints_text}\n")

        parts.append(
            "\n## Task\n"
            "Analyze this codebase for security vulnerabilities.\n"
            "Return a JSON array of vulnerability objects.\n"
            "Focus on Critical and High severity findings with concrete evidence."
        )

        return "\n".join(parts)

    def _parse_response(self, content: str) -> DiscoveryResult:
        """Parse LLM response into structured vulnerability drafts."""
        try:
            # Extract JSON from response (handle markdown code blocks)
            json_str = content
            if "```json" in content:
                json_str = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                json_str = content.split("```")[1].split("```")[0]

            raw_vulns = json.loads(json_str)

            if not isinstance(raw_vulns, list):
                raw_vulns = [raw_vulns]

            drafts = []
            for idx, raw in enumerate(raw_vulns):
                try:
                    draft = VulnerabilityDraft(
                        vulnerability_id=raw.get("vulnerability_id", f"VULN-{idx + 1:03d}"),
                        cwe_class=raw.get("cwe_class", "Unknown"),
                        severity=raw.get("severity", "Medium"),
                        title=raw.get("title", "Unnamed Vulnerability"),
                        description=raw.get("description", ""),
                        source_file=raw.get("source_file", ""),
                        source_line=int(raw.get("source_line", 0)),
                        source_input_type=raw.get("source_input_type", ""),
                        sink_file=raw.get("sink_file", ""),
                        sink_line=int(raw.get("sink_line", 0)),
                        sink_operation=raw.get("sink_operation", ""),
                        data_flow=raw.get("data_flow", []),
                        missing_guard=raw.get("missing_guard", ""),
                        exploit_hypothesis=raw.get("exploit_hypothesis", ""),
                        confidence=float(raw.get("confidence", 0.5)),
                    )
                    drafts.append(draft)
                except (ValueError, TypeError):
                    continue

            return DiscoveryResult(
                vulnerabilities=drafts,
                total_candidates=len(drafts),
            )

        except (json.JSONDecodeError, IndexError):
            return DiscoveryResult()

    async def _reason(
        self,
        prompt: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute LLM reasoning for vulnerability analysis."""
        return await self._call_llm(prompt)
