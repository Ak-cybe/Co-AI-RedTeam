"""Tests for SARIF and Markdown report generation."""

import json
import tempfile
from pathlib import Path

import pytest

from co_redteam.agents.analysis import VulnerabilityDraft
from co_redteam.agents.patcher import PatchCandidate
from co_redteam.reporting.markdown import MarkdownReporter
from co_redteam.reporting.sarif import SarifGenerator


@pytest.fixture
def sample_vulns() -> list[VulnerabilityDraft]:
    """Sample vulnerabilities for testing."""
    return [
        VulnerabilityDraft(
            vulnerability_id="VULN-001",
            cwe_class="CWE-89: SQL Injection",
            severity="Critical",
            title="SQL Injection in user query",
            description="User input interpolated directly into SQL query",
            source_file="src/routes/users.py",
            source_line=42,
            source_input_type="query parameter",
            sink_file="src/db/queries.py",
            sink_line=78,
            sink_operation="cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
            data_flow=[
                "request.args.get('id') → user_id",
                "user_id passed to get_user()",
                "get_user() builds SQL via f-string",
            ],
            missing_guard="No parameterized query",
            exploit_hypothesis="Inject ' OR 1=1-- to dump all records",
            confidence=0.95,
        ),
        VulnerabilityDraft(
            vulnerability_id="VULN-002",
            cwe_class="CWE-79: Cross-site Scripting",
            severity="High",
            title="Reflected XSS in search",
            description="User search term rendered without HTML encoding",
            source_file="src/routes/search.py",
            source_line=15,
            source_input_type="query parameter",
            sink_file="src/templates/results.html",
            sink_line=22,
            sink_operation="{{ query | safe }}",
            data_flow=["request.args.get('q') → query", "query passed to template"],
            missing_guard="No HTML escaping",
            exploit_hypothesis="Inject <script>alert(1)</script>",
            confidence=0.88,
        ),
    ]


@pytest.fixture
def sample_patch() -> PatchCandidate:
    """Sample patch for testing."""
    return PatchCandidate(
        patch_id="PATCH-001",
        vulnerability_id="VULN-001",
        file_path="src/db/queries.py",
        original_code="cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
        patched_code="cursor.execute('SELECT * FROM users WHERE id=%s', (user_id,))",
        diff=(
            "-cursor.execute(f'SELECT * FROM users WHERE id={user_id}')\n"
            "+cursor.execute('SELECT * FROM users WHERE id=%s', (user_id,))"
        ),
        fix_description="Use parameterized query",
        cwe_fix_pattern="Parameterized Query",
        confidence=0.92,
    )


class TestSarifGenerator:
    """Test SARIF report generation."""

    def test_basic_generation(self, sample_vulns: list[VulnerabilityDraft]) -> None:
        gen = SarifGenerator()
        sarif = gen.generate(sample_vulns)

        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1

        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "Co-AI-RedTeam"
        assert len(run["results"]) == 2

    def test_severity_mapping(self, sample_vulns: list[VulnerabilityDraft]) -> None:
        gen = SarifGenerator()
        sarif = gen.generate(sample_vulns)

        results = sarif["runs"][0]["results"]
        assert results[0]["level"] == "error"  # Critical → error
        assert results[1]["level"] == "error"  # High → error

    def test_code_flows(self, sample_vulns: list[VulnerabilityDraft]) -> None:
        gen = SarifGenerator()
        sarif = gen.generate(sample_vulns)

        result = sarif["runs"][0]["results"][0]
        assert "codeFlows" in result
        flow_locations = result["codeFlows"][0]["threadFlows"][0]["locations"]
        assert len(flow_locations) == 3  # 3 data flow steps

    def test_with_patches(
        self,
        sample_vulns: list[VulnerabilityDraft],
        sample_patch: PatchCandidate,
    ) -> None:
        gen = SarifGenerator()
        sarif = gen.generate(sample_vulns, patches=[sample_patch])

        result = sarif["runs"][0]["results"][0]
        assert "fixes" in result
        assert result["fixes"][0]["description"]["text"] == "Use parameterized query"

    def test_file_output(self, sample_vulns: list[VulnerabilityDraft]) -> None:
        gen = SarifGenerator()

        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            gen.generate(sample_vulns, output_path=tmp_path)
            assert tmp_path.exists()

            data = json.loads(tmp_path.read_text())
            assert data["version"] == "2.1.0"
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_cwe_taxonomies(self, sample_vulns: list[VulnerabilityDraft]) -> None:
        gen = SarifGenerator()
        sarif = gen.generate(sample_vulns)

        taxonomies = sarif["runs"][0].get("taxonomies", [])
        assert len(taxonomies) == 1
        assert taxonomies[0]["name"] == "CWE"
        assert len(taxonomies[0]["taxa"]) == 2  # CWE-89 and CWE-79


class TestMarkdownReporter:
    """Test Markdown report generation."""

    def test_basic_report(self, sample_vulns: list[VulnerabilityDraft]) -> None:
        reporter = MarkdownReporter()
        report = reporter.generate(
            target_name="test-project",
            vulnerabilities=sample_vulns,
            scan_duration_seconds=42.5,
        )

        assert "# 🛡️ Security Assessment Report" in report
        assert "test-project" in report
        assert "VULN-001" in report
        assert "VULN-002" in report
        assert "SQL Injection" in report
        assert "42.5s" in report

    def test_empty_report(self) -> None:
        reporter = MarkdownReporter()
        report = reporter.generate(
            target_name="clean-project",
            vulnerabilities=[],
        )

        assert "No vulnerabilities discovered" in report

    def test_severity_breakdown(self, sample_vulns: list[VulnerabilityDraft]) -> None:
        reporter = MarkdownReporter()
        report = reporter.generate(
            target_name="test-project",
            vulnerabilities=sample_vulns,
        )

        assert "Critical" in report
        assert "High" in report

    def test_remediation_priority(self, sample_vulns: list[VulnerabilityDraft]) -> None:
        reporter = MarkdownReporter()
        report = reporter.generate(
            target_name="test",
            vulnerabilities=sample_vulns,
        )

        assert "Remediation Priority" in report

    def test_file_output(self, sample_vulns: list[VulnerabilityDraft]) -> None:
        reporter = MarkdownReporter()

        with tempfile.NamedTemporaryFile(suffix=".md", delete=False, mode="w") as tmp:
            tmp_path = Path(tmp.name)

        try:
            reporter.generate(
                target_name="test",
                vulnerabilities=sample_vulns,
                output_path=tmp_path,
            )
            assert tmp_path.exists()
            content = tmp_path.read_text(encoding="utf-8")
            assert "VULN-001" in content
        finally:
            tmp_path.unlink(missing_ok=True)
