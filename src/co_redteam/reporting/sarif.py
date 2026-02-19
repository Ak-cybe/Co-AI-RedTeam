"""
SARIF v2.1.0 Report Generator.

Converts Co-AI-RedTeam findings into standardized SARIF JSON
for GitHub Code Scanning, Azure DevOps, and CI/CD integration.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from co_redteam.agents.analysis import VulnerabilityDraft
from co_redteam.agents.patcher import PatchCandidate

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "main/sarif-2.1/schema/sarif-schema-2.1.0.json"
)

SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "informational": "none",
}


class SarifGenerator:
    """Generates SARIF v2.1.0 reports from security findings."""

    def __init__(
        self,
        tool_name: str = "Co-AI-RedTeam",
        tool_version: str = "0.1.0",
        tool_uri: str = "https://github.com/co-ai-redteam/co-ai-redteam",
    ) -> None:
        self.tool_name = tool_name
        self.tool_version = tool_version
        self.tool_uri = tool_uri

    def generate(
        self,
        vulnerabilities: list[VulnerabilityDraft],
        patches: list[PatchCandidate] | None = None,
        output_path: Path | None = None,
    ) -> dict[str, Any]:
        """
        Generate a SARIF report from vulnerability findings.

        Args:
            vulnerabilities: Discovered vulnerabilities.
            patches: Optional patches generated for the vulnerabilities.
            output_path: Optional file path to write the SARIF JSON.

        Returns:
            Complete SARIF v2.1.0 JSON structure.
        """
        patches_map: dict[str, PatchCandidate] = {}
        if patches:
            for patch in patches:
                patches_map[patch.vulnerability_id] = patch

        rules = self._build_rules(vulnerabilities)
        results = self._build_results(vulnerabilities, patches_map)

        sarif = {
            "$schema": SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.tool_name,
                            "version": self.tool_version,
                            "informationUri": self.tool_uri,
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": datetime.now(timezone.utc).isoformat(),
                        }
                    ],
                    "taxonomies": self._build_taxonomies(vulnerabilities),
                }
            ],
        }

        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(
                json.dumps(sarif, indent=2, default=str),
                encoding="utf-8",
            )

        return sarif

    def _build_rules(self, vulnerabilities: list[VulnerabilityDraft]) -> list[dict[str, Any]]:
        """Build SARIF rule definitions from vulnerabilities."""
        rules = []
        seen_ids: set[str] = set()

        for vuln in vulnerabilities:
            if vuln.vulnerability_id in seen_ids:
                continue
            seen_ids.add(vuln.vulnerability_id)

            level = SEVERITY_TO_SARIF_LEVEL.get(vuln.severity.lower(), "warning")

            cwe_id = ""
            if vuln.cwe_class.startswith("CWE-"):
                cwe_id = vuln.cwe_class.split(":")[0].split("-")[1]

            tags = ["security"]
            if cwe_id:
                tags.append(f"CWE-{cwe_id}")
            tags.append(f"severity/{vuln.severity.lower()}")

            rule: dict[str, Any] = {
                "id": vuln.vulnerability_id,
                "name": vuln.title.replace(" ", ""),
                "shortDescription": {"text": vuln.title},
                "fullDescription": {"text": vuln.description},
                "defaultConfiguration": {"level": level},
                "properties": {"tags": tags},
            }
            if cwe_id:
                rule["helpUri"] = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"

            rules.append(rule)

        return rules

    def _build_results(
        self,
        vulnerabilities: list[VulnerabilityDraft],
        patches_map: dict[str, PatchCandidate],
    ) -> list[dict[str, Any]]:
        """Build SARIF result entries from vulnerabilities."""
        results = []

        for vuln in vulnerabilities:
            level = SEVERITY_TO_SARIF_LEVEL.get(vuln.severity.lower(), "warning")

            result: dict[str, Any] = {
                "ruleId": vuln.vulnerability_id,
                "level": level,
                "message": {"text": (f"{vuln.title}: {vuln.description[:200]}")},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": vuln.sink_file.replace("\\", "/"),
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": max(1, vuln.sink_line),
                                "startColumn": 1,
                            },
                        }
                    }
                ],
            }

            # Add code flow if source != sink
            if vuln.source_file and vuln.data_flow:
                thread_flow_locations = []
                for idx, step in enumerate(vuln.data_flow):
                    thread_flow_locations.append(
                        {
                            "location": {
                                "message": {"text": step},
                            },
                            "nestingLevel": 0,
                            "executionOrder": idx + 1,
                        }
                    )

                result["codeFlows"] = [{"threadFlows": [{"locations": thread_flow_locations}]}]

            # Add fix if patch exists
            patch = patches_map.get(vuln.vulnerability_id)
            if patch and patch.patched_code:
                result["fixes"] = [
                    {
                        "description": {"text": patch.fix_description},
                        "artifactChanges": [
                            {
                                "artifactLocation": {"uri": patch.file_path.replace("\\", "/")},
                                "replacements": [
                                    {
                                        "deletedRegion": {
                                            "startLine": vuln.sink_line,
                                            "endLine": vuln.sink_line,
                                        },
                                        "insertedContent": {
                                            "text": patch.patched_code,
                                        },
                                    }
                                ],
                            }
                        ],
                    }
                ]

            results.append(result)

        return results

    def _build_taxonomies(self, vulnerabilities: list[VulnerabilityDraft]) -> list[dict[str, Any]]:
        """Build CWE taxonomy references."""
        taxa = []
        seen_cwes: set[str] = set()

        for vuln in vulnerabilities:
            if not vuln.cwe_class.startswith("CWE-"):
                continue

            parts = vuln.cwe_class.split(":")
            cwe_id = parts[0].replace("CWE-", "").strip()
            cwe_name = parts[1].strip() if len(parts) > 1 else ""

            if cwe_id in seen_cwes:
                continue
            seen_cwes.add(cwe_id)

            taxa.append(
                {
                    "id": cwe_id,
                    "name": cwe_name or f"CWE-{cwe_id}",
                    "shortDescription": {"text": vuln.cwe_class},
                }
            )

        return (
            [
                {
                    "name": "CWE",
                    "version": "4.14",
                    "informationUri": "https://cwe.mitre.org/",
                    "taxa": taxa,
                }
            ]
            if taxa
            else []
        )
