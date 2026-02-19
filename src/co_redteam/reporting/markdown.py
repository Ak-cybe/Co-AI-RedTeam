"""
Markdown Report Generator.

Generates a polished, executive-ready security assessment report
with vulnerability details, evidence chains, patches, and statistics.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from co_redteam.agents.analysis import VulnerabilityDraft
from co_redteam.agents.critique import CritiqueResult, ReviewStatus
from co_redteam.agents.patcher import PatchCandidate

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "informational": "⚪",
}


class MarkdownReporter:
    """Generates publication-ready Markdown security reports."""

    def generate(
        self,
        target_name: str,
        vulnerabilities: list[VulnerabilityDraft],
        critiques: list[CritiqueResult] | None = None,
        patches: list[PatchCandidate] | None = None,
        scan_duration_seconds: float = 0.0,
        output_path: Path | None = None,
    ) -> str:
        """
        Generate the full assessment report.

        Returns:
            Complete Markdown report as a string.
        """
        critiques_map: dict[str, CritiqueResult] = {}
        if critiques:
            for critique in critiques:
                critiques_map[critique.vulnerability_id] = critique

        patches_map: dict[str, PatchCandidate] = {}
        if patches:
            for patch in patches:
                patches_map[patch.vulnerability_id] = patch

        # Only include approved vulnerabilities
        approved = [
            v
            for v in vulnerabilities
            if v.vulnerability_id not in critiques_map
            or critiques_map[v.vulnerability_id].status == ReviewStatus.APPROVED
        ]

        sections = [
            self._header(target_name),
            self._executive_summary(approved, scan_duration_seconds),
            self._severity_breakdown(approved),
            self._detailed_findings(approved, critiques_map, patches_map),
            self._remediation_priority(approved, patches_map),
            self._methodology(),
            self._footer(),
        ]

        report = "\n\n".join(sections)

        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(report, encoding="utf-8")

        return report

    def _header(self, target_name: str) -> str:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        return (
            f"# 🛡️ Security Assessment Report\n\n"
            f"**Target:** `{target_name}`\n"
            f"**Date:** {timestamp}\n"
            f"**Tool:** Co-AI-RedTeam v0.1.0\n"
            f"**Framework:** Co-RedTeam Multi-Agent Pipeline\n\n"
            f"---"
        )

    def _executive_summary(
        self,
        vulns: list[VulnerabilityDraft],
        duration: float,
    ) -> str:
        severity_counts: dict[str, int] = {}
        for vuln in vulns:
            key = vuln.severity.lower()
            severity_counts[key] = severity_counts.get(key, 0) + 1

        critical = severity_counts.get("critical", 0)
        high = severity_counts.get("high", 0)
        medium = severity_counts.get("medium", 0)
        low = severity_counts.get("low", 0)

        duration_str = f"{duration:.1f}s" if duration < 60 else f"{duration / 60:.1f}m"

        risk_level = (
            "🔴 CRITICAL"
            if critical > 0
            else "🟠 HIGH"
            if high > 0
            else "🟡 MODERATE"
            if medium > 0
            else "🟢 LOW"
        )

        return (
            f"## Executive Summary\n\n"
            f"| Metric | Value |\n"
            f"|--------|-------|\n"
            f"| **Overall Risk** | {risk_level} |\n"
            f"| **Total Findings** | {len(vulns)} |\n"
            f"| **Critical** | {critical} |\n"
            f"| **High** | {high} |\n"
            f"| **Medium** | {medium} |\n"
            f"| **Low** | {low} |\n"
            f"| **Scan Duration** | {duration_str} |"
        )

    def _severity_breakdown(self, vulns: list[VulnerabilityDraft]) -> str:
        if not vulns:
            return "## Findings\n\n✅ No vulnerabilities discovered."

        lines = ["## Severity Breakdown\n"]
        for severity in ["critical", "high", "medium", "low"]:
            count = sum(1 for v in vulns if v.severity.lower() == severity)
            if count > 0:
                emoji = SEVERITY_EMOJI.get(severity, "⚪")
                bar = "█" * count
                lines.append(f"{emoji} **{severity.capitalize()}**: {bar} ({count})")

        return "\n".join(lines)

    def _detailed_findings(
        self,
        vulns: list[VulnerabilityDraft],
        critiques_map: dict[str, CritiqueResult],
        patches_map: dict[str, PatchCandidate],
    ) -> str:
        if not vulns:
            return ""

        sections = ["## Detailed Findings\n"]

        for vuln in vulns:
            emoji = SEVERITY_EMOJI.get(vuln.severity.lower(), "⚪")
            critique = critiques_map.get(vuln.vulnerability_id)
            patch = patches_map.get(vuln.vulnerability_id)

            section = (
                f"### {emoji} {vuln.vulnerability_id}: {vuln.title}\n\n"
                f"| Property | Value |\n"
                f"|----------|-------|\n"
                f"| **CWE** | {vuln.cwe_class} |\n"
                f"| **Severity** | {vuln.severity} |\n"
                f"| **Confidence** | {vuln.confidence:.0%} |\n"
                f"| **Source** | `{vuln.source_file}:{vuln.source_line}` |\n"
                f"| **Sink** | `{vuln.sink_file}:{vuln.sink_line}` |\n\n"
                f"**Description:** {vuln.description}\n\n"
                f"**Vulnerable Operation:**\n```\n{vuln.sink_operation}\n```\n\n"
                f"**Data Flow:**\n"
            )

            for step in vuln.data_flow:
                section += f"1. {step}\n"

            section += f"\n**Missing Guard:** {vuln.missing_guard}\n"
            section += f"\n**Exploit Hypothesis:** {vuln.exploit_hypothesis}\n"

            if critique:
                section += (
                    f"\n**Critique Review:** {critique.status.value.upper()} "
                    f"— {critique.reasoning}\n"
                )

            if patch and patch.patched_code:
                section += (
                    f"\n**🔧 Suggested Fix:**\n"
                    f"```diff\n{patch.diff}\n```\n"
                    f"_{patch.fix_description}_\n"
                )

            sections.append(section)

        return "\n---\n\n".join(sections)

    def _remediation_priority(
        self,
        vulns: list[VulnerabilityDraft],
        patches_map: dict[str, PatchCandidate],
    ) -> str:
        if not vulns:
            return ""

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_vulns = sorted(vulns, key=lambda v: severity_order.get(v.severity.lower(), 4))

        lines = [
            "## Remediation Priority\n\n"
            "| Priority | ID | Title | Severity | Patch Available |\n"
            "|----------|----|-------|----------|-----------------|\n"
        ]

        for idx, vuln in enumerate(sorted_vulns, 1):
            has_patch = "✅" if vuln.vulnerability_id in patches_map else "❌"
            emoji = SEVERITY_EMOJI.get(vuln.severity.lower(), "⚪")
            lines.append(
                f"| {idx} | {vuln.vulnerability_id} | {vuln.title} "
                f"| {emoji} {vuln.severity} | {has_patch} |"
            )

        return "\n".join(lines)

    def _methodology(self) -> str:
        return (
            "## Methodology\n\n"
            "This assessment used the **Co-AI-RedTeam** multi-agent framework, "
            "implementing the Co-RedTeam pipeline:\n\n"
            "1. **Discovery (Stage I):** Analysis Agent explores code with CWE/OWASP grounding, "
            "Critique Agent validates evidence chains and filters false positives.\n"
            "2. **Exploitation (Stage II):** Planner Agent creates explicit exploit plans, "
            "Executor Agent runs in sandboxed environment, "
            "Evaluator Agent provides execution feedback.\n"
            "3. **Patching:** Root Cause Analysis → Patch Generation → Validation "
            "with LLM reflection on failures.\n"
            "4. **Memory:** Findings stored in 3-layer memory for "
            "continuous improvement across assessments.\n\n"
            "**References:**\n"
            "- [Co-RedTeam: Orchestrated Security Discovery and Exploitation with LLM Agents](https://arxiv.org/abs/2602.02164)\n"
            "- [SoK: DARPA's AI Cyber Challenge (AIxCC)](https://arxiv.org/abs/2602.07666)"
        )

    def _footer(self) -> str:
        return (
            "---\n\n"
            "*Generated by [Co-AI-RedTeam](https://github.com/co-ai-redteam/co-ai-redteam) — "
            "AI-powered multi-agent red teaming.*\n\n"
            "⚠️ **Disclaimer:** This report is generated by an AI system. "
            "Findings should be verified by qualified security professionals "
            "before taking remediation actions."
        )
