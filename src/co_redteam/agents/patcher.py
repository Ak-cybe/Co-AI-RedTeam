"""
Patcher Agent — Generates and validates security patches.

Implements the AIxCC CRS patch pipeline:
RCA → Generate → Validate loop with LLM reflection.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field

from co_redteam.agents.base import AgentRole, BaseAgent
from co_redteam.config import LLMConfig


class PatchCandidate(BaseModel):
    """A generated security patch."""

    patch_id: str
    vulnerability_id: str
    file_path: str
    original_code: str
    patched_code: str
    diff: str
    fix_description: str
    cwe_fix_pattern: str
    confidence: float = Field(ge=0.0, le=1.0, default=0.7)


class PatchValidation(BaseModel):
    """Validation results for a patch."""

    patch_id: str
    build_passes: bool = False
    pov_blocked: bool = False
    tests_pass: bool = False
    no_regressions: bool = False
    overall_valid: bool = False
    failure_reason: str = ""


class RootCauseAnalysis(BaseModel):
    """Root cause analysis for a vulnerability."""

    vulnerability_id: str
    cwe_class: str
    root_cause_file: str
    root_cause_line: int
    root_cause_description: str
    trigger_mechanism: str
    fix_scope: list[str]
    fix_strategy: str


PATCHER_SYSTEM_PROMPT = """You are a security patch engineer. Given a vulnerability with its root cause, generate a MINIMAL, CORRECT patch.

PATCHING PRINCIPLES:
1. **Minimal Diff**: Only change what's necessary to fix the vulnerability
2. **Defense in Depth**: Prefer fail-closed over fail-open
3. **Convention Following**: Match existing code style
4. **Non-Breaking**: Preserve existing functionality and APIs
5. **No TODO Comments**: Implement the fix completely

FIX PATTERNS BY CWE:
- CWE-89 (SQLi): Use parameterized queries
- CWE-78 (CMDi): Use argument lists, shell=False
- CWE-79 (XSS): HTML-encode output
- CWE-22 (Path Traversal): Canonicalize and validate paths
- CWE-918 (SSRF): URL allowlisting
- CWE-502 (Deser): Use safe formats (JSON instead of pickle)
- CWE-287 (Auth): Add proper authentication checks
- CWE-798 (Hardcoded): Move to env vars/secret store

OUTPUT FORMAT: JSON with:
- patch_id, vulnerability_id, file_path
- original_code: the exact vulnerable code
- patched_code: the fixed code
- diff: unified diff format
- fix_description: what the patch does
- cwe_fix_pattern: which CWE fix pattern was applied
- confidence: 0.0-1.0"""


class PatcherAgent(BaseAgent):
    """
    Security patch generation agent.

    Performs root cause analysis and generates minimal,
    validated security patches with reflection-based retry.
    """

    def __init__(self, llm_config: LLMConfig) -> None:
        super().__init__(
            role=AgentRole.PATCHER,
            llm_config=llm_config,
            system_prompt=PATCHER_SYSTEM_PROMPT,
        )

    async def analyze_root_cause(
        self,
        vulnerability_description: str,
        code_context: str,
    ) -> RootCauseAnalysis:
        """
        Perform root cause analysis for a vulnerability.

        Separates understanding from fixing — RCA first, then patch.
        """
        prompt = (
            f"## Vulnerability\n{vulnerability_description}\n\n"
            f"## Code Context\n```\n{code_context}\n```\n\n"
            f"## Task\nPerform Root Cause Analysis.\n"
            f"Return JSON with: vulnerability_id, cwe_class, root_cause_file, "
            f"root_cause_line, root_cause_description, trigger_mechanism, "
            f"fix_scope (array of file:line ranges), fix_strategy."
        )

        response = await self.invoke(prompt)
        if not response.success:
            return RootCauseAnalysis(
                vulnerability_id="unknown",
                cwe_class="unknown",
                root_cause_file="",
                root_cause_line=0,
                root_cause_description="RCA failed",
                trigger_mechanism="",
                fix_scope=[],
                fix_strategy="",
            )

        return self._parse_rca(response.content)

    async def generate_patch(
        self,
        rca: RootCauseAnalysis,
        code_context: str,
        prior_failed_patches: list[str] | None = None,
    ) -> PatchCandidate:
        """
        Generate a security patch based on RCA.

        Args:
            rca: Root cause analysis results.
            code_context: The vulnerable code.
            prior_failed_patches: Failed patches from previous iterations (for reflection).

        Returns:
            PatchCandidate with the fix.
        """
        parts = [
            f"## Root Cause Analysis\n```json\n{rca.model_dump_json(indent=2)}\n```\n\n",
            f"## Vulnerable Code\n```\n{code_context}\n```\n\n",
        ]

        if prior_failed_patches:
            failures = "\n---\n".join(prior_failed_patches)
            parts.append(
                f"## ⚠️ Prior Failed Patches (DO NOT repeat these mistakes)\n{failures}\n\n"
            )

        parts.append("## Task\nGenerate a MINIMAL security patch. Return JSON.")

        prompt = "\n".join(parts)
        response = await self.invoke(prompt)

        if not response.success:
            return PatchCandidate(
                patch_id="PATCH-FAIL",
                vulnerability_id=rca.vulnerability_id,
                file_path=rca.root_cause_file,
                original_code="",
                patched_code="",
                diff="",
                fix_description="Patch generation failed",
                cwe_fix_pattern="",
                confidence=0.0,
            )

        return self._parse_patch(response.content, rca)

    def _parse_rca(self, content: str) -> RootCauseAnalysis:
        """Parse RCA response."""
        try:
            json_str = content
            if "```json" in content:
                json_str = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                json_str = content.split("```")[1].split("```")[0]

            raw = json.loads(json_str)
            return RootCauseAnalysis(
                vulnerability_id=raw.get("vulnerability_id", "unknown"),
                cwe_class=raw.get("cwe_class", "unknown"),
                root_cause_file=raw.get("root_cause_file", ""),
                root_cause_line=int(raw.get("root_cause_line", 0)),
                root_cause_description=raw.get("root_cause_description", ""),
                trigger_mechanism=raw.get("trigger_mechanism", ""),
                fix_scope=raw.get("fix_scope", []),
                fix_strategy=raw.get("fix_strategy", ""),
            )
        except (json.JSONDecodeError, IndexError):
            return RootCauseAnalysis(
                vulnerability_id="unknown",
                cwe_class="unknown",
                root_cause_file="",
                root_cause_line=0,
                root_cause_description="Failed to parse RCA",
                trigger_mechanism="",
                fix_scope=[],
                fix_strategy="",
            )

    def _parse_patch(self, content: str, rca: RootCauseAnalysis) -> PatchCandidate:
        """Parse patch response."""
        try:
            json_str = content
            if "```json" in content:
                json_str = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                json_str = content.split("```")[1].split("```")[0]

            raw = json.loads(json_str)
            return PatchCandidate(
                patch_id=raw.get("patch_id", "PATCH-001"),
                vulnerability_id=rca.vulnerability_id,
                file_path=raw.get("file_path", rca.root_cause_file),
                original_code=raw.get("original_code", ""),
                patched_code=raw.get("patched_code", ""),
                diff=raw.get("diff", ""),
                fix_description=raw.get("fix_description", ""),
                cwe_fix_pattern=raw.get("cwe_fix_pattern", ""),
                confidence=float(raw.get("confidence", 0.7)),
            )
        except (json.JSONDecodeError, IndexError):
            return PatchCandidate(
                patch_id="PATCH-FAIL",
                vulnerability_id=rca.vulnerability_id,
                file_path=rca.root_cause_file,
                original_code="",
                patched_code="",
                diff="",
                fix_description="Failed to parse patch",
                cwe_fix_pattern="",
                confidence=0.0,
            )

    async def _reason(
        self,
        prompt: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute LLM reasoning for patching."""
        return await self._call_llm(prompt, temperature=0.1)
