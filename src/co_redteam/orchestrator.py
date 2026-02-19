"""
Co-AI-RedTeam Orchestrator — Central pipeline coordinator.

Implements the Co-RedTeam orchestrator pattern:
  Recon → Discovery → Exploitation → Patching → Reporting

Manages agent lifecycle, state transitions, and experience accumulation.
"""

from __future__ import annotations

import fnmatch
import logging
import time
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from co_redteam.agents.analysis import AnalysisAgent, DiscoveryResult, VulnerabilityDraft
from co_redteam.agents.critique import CritiqueAgent, CritiqueResult, ReviewStatus
from co_redteam.agents.evaluator import EvaluatorAgent
from co_redteam.agents.executor import ExecutorAgent
from co_redteam.agents.patcher import PatchCandidate, PatcherAgent
from co_redteam.agents.planner import ExploitPlan, PlannerAgent
from co_redteam.agents.validator import ValidatorAgent
from co_redteam.config import RedTeamConfig
from co_redteam.memory.store import MemoryStore
from co_redteam.reporting.markdown import MarkdownReporter
from co_redteam.reporting.sarif import SarifGenerator

console = Console()
logger = logging.getLogger(__name__)


class PipelineState:
    """Tracks the state of a red team assessment pipeline."""

    def __init__(self) -> None:
        self.start_time: float = time.time()
        self.file_tree: str = ""
        self.tech_stack: str = ""
        self.code_context: str = ""
        self.files_scanned: int = 0

        # Stage outputs
        self.discovery_result: DiscoveryResult | None = None
        self.critiques: list[CritiqueResult] = []
        self.approved_vulns: list[VulnerabilityDraft] = []
        self.exploit_plans: list[ExploitPlan] = []
        self.patches: list[PatchCandidate] = []

        # Metrics
        self.total_tokens: int = 0
        self.total_llm_calls: int = 0

    @property
    def duration_seconds(self) -> float:
        return time.time() - self.start_time


class Orchestrator:
    """
    Central orchestrator for the Co-AI-RedTeam pipeline.

    Coordinates:
    - Reconnaissance (file tree, tech stack detection)
    - Discovery (Analysis + Critique loop)
    - Exploitation (Plan → Execute → Evaluate loop)
    - Patching (RCA → Generate → Validate loop)
    - Reporting (SARIF + Markdown)
    - Memory (experience accumulation)
    """

    def __init__(self, config: RedTeamConfig) -> None:
        self.config = config

        # Initialize agents
        self.analysis_agent = AnalysisAgent(config.llm)
        self.critique_agent = CritiqueAgent(config.llm)
        self.planner_agent = PlannerAgent(config.llm)
        self.validator_agent = ValidatorAgent(config.llm)
        self.executor_agent = ExecutorAgent(config.llm, config.sandbox)
        self.evaluator_agent = EvaluatorAgent(config.llm)
        self.patcher_agent = PatcherAgent(config.llm)

        # Initialize memory
        self.memory = MemoryStore(config.memory.storage_dir) if config.memory.enabled else None

        # Initialize reporters
        self.sarif_gen = SarifGenerator()
        self.md_reporter = MarkdownReporter()

        # State
        self.state = PipelineState()

    async def run(self) -> dict[str, Any]:
        """
        Execute the full red team assessment pipeline.

        Returns:
            Summary dict with findings, patches, and report paths.
        """
        console.print(
            Panel.fit(
                "[bold red]Co-AI-RedTeam[/bold red] 🛡️\n[dim]Multi-Agent Red Team Assessment[/dim]",
                border_style="red",
            )
        )

        target = self.config.target_path

        # Phase 1: Reconnaissance
        await self._phase_recon(target)

        # Phase 2: Vulnerability Discovery
        await self._phase_discovery()

        # Phase 3: Exploitation (for Critical/High findings)
        if self.state.approved_vulns and self.config.exploit.enabled:
            await self._phase_exploitation()

        # Phase 4: Patching
        if self.state.approved_vulns and self.config.patch.enabled:
            await self._phase_patching()

        # Phase 5: Reporting
        report_paths = await self._phase_reporting(target)

        # Phase 6: Memory accumulation
        if self.memory:
            await self._phase_memory()

        # Summary
        self._print_summary()

        return {
            "vulnerabilities_found": len(self.state.approved_vulns),
            "patches_generated": len(self.state.patches),
            "report_paths": report_paths,
            "duration_seconds": self.state.duration_seconds,
        }

    async def _phase_recon(self, target: Path) -> None:
        """Phase 1: Reconnaissance — map codebase and detect tech stack."""
        console.print("\n[bold cyan]⟐ Phase 1: Reconnaissance[/bold cyan]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning file tree...", total=None)

            self.state.file_tree = self._build_file_tree(target)
            progress.update(task, description="Detecting tech stack...")

            self.state.tech_stack = self._detect_tech_stack(target)
            progress.update(task, description="Reading source files...")

            self.state.code_context = self._read_source_files(target)
            progress.update(task, description="Reconnaissance complete ✓")

        console.print(f"  📁 Files scanned: [green]{self.state.files_scanned}[/green]")
        console.print(f"  🔧 Tech stack: [green]{self.state.tech_stack}[/green]")

    async def _phase_discovery(self) -> None:
        """Phase 2: Discovery — Analysis + Critique loop."""
        console.print("\n[bold cyan]⟐ Phase 2: Vulnerability Discovery[/bold cyan]")

        # Retrieve memory hints
        memory_hints: list[str] = []
        if self.memory:
            patterns = self.memory.get_all_patterns()
            memory_hints = [f"{p.cwe_class}: {p.pattern_name} — {p.symptom}" for p in patterns[:5]]

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Analysis Agent scanning...", total=None)

            # Analysis pass
            self.state.discovery_result = await self.analysis_agent.analyze_codebase(
                code_context=self.state.code_context,
                file_tree=self.state.file_tree,
                tech_stack=self.state.tech_stack,
                memory_hints=memory_hints if memory_hints else None,
            )

            initial_count = len(self.state.discovery_result.vulnerabilities)
            console.print(f"  🔍 Analysis Agent found [yellow]{initial_count}[/yellow] candidates")

            # Analysis-Critique refinement loop (Co-RedTeam §3.2)
            current_drafts = self.state.discovery_result.vulnerabilities
            for iteration in range(self.config.discovery.max_critique_iterations):
                progress.update(
                    task,
                    description=f"Critique iteration {iteration + 1}/"
                    f"{self.config.discovery.max_critique_iterations}...",
                )

                critiques = await self.critique_agent.review_vulnerabilities(
                    drafts=current_drafts,
                    code_context=self.state.code_context,
                )
                self.state.critiques = critiques

                # Separate by review status
                approved = []
                needs_refinement = []
                for draft in current_drafts:
                    matching_critique = next(
                        (c for c in critiques if c.vulnerability_id == draft.vulnerability_id),
                        None,
                    )
                    if matching_critique and matching_critique.status == ReviewStatus.APPROVED:
                        draft.confidence = matching_critique.adjusted_confidence
                        approved.append(draft)
                    elif (
                        matching_critique
                        and matching_critique.status == ReviewStatus.NEEDS_REFINEMENT
                    ):
                        needs_refinement.append((draft, matching_critique))

                approved_count = sum(1 for c in critiques if c.status == ReviewStatus.APPROVED)
                rejected_count = sum(1 for c in critiques if c.status == ReviewStatus.REJECTED)
                refine_count = len(needs_refinement)
                console.print(
                    f"  ✓ Critique {iteration + 1}: "
                    f"[green]{approved_count} approved[/green], "
                    f"[red]{rejected_count} rejected[/red], "
                    f"[yellow]{refine_count} needs refinement[/yellow]"
                )

                # Re-invoke Analysis Agent with critique feedback for NEEDS_REFINEMENT items
                if needs_refinement and iteration < self.config.discovery.max_critique_iterations - 1:
                    feedback_hints = []
                    for draft, critique in needs_refinement:
                        suggestions_text = (
                            ", ".join(critique.suggestions)
                            if critique.suggestions
                            else "Strengthen evidence chain."
                        )
                        feedback_hints.append(
                            f"Revisit {draft.vulnerability_id} ({draft.title}): "
                            f"{critique.reasoning}. Suggestions: {suggestions_text}"
                        )
                    progress.update(task, description="Analysis Agent refining findings...")
                    refined_result = await self.analysis_agent.analyze_codebase(
                        code_context=self.state.code_context,
                        file_tree=self.state.file_tree,
                        tech_stack=self.state.tech_stack,
                        memory_hints=feedback_hints,
                    )
                    # Merge refined findings with already-approved ones
                    current_drafts = approved + refined_result.vulnerabilities
                else:
                    current_drafts = approved

                # Stop early if all approved or rejected (none need refinement)
                if all(
                    c.status in (ReviewStatus.APPROVED, ReviewStatus.REJECTED) for c in critiques
                ):
                    break

        # Final approved list — filter by confidence
        self.state.approved_vulns = [
            v for v in current_drafts if v.confidence >= self.config.discovery.min_confidence
        ]

        console.print(
            f"\n  📊 [bold]Final: {len(self.state.approved_vulns)} confirmed vulnerabilities[/bold]"
        )

    async def _phase_exploitation(self) -> None:
        """Phase 3: Exploitation — Plan → Execute → Evaluate loop."""
        console.print("\n[bold cyan]⟐ Phase 3: Exploitation[/bold cyan]")

        # Only attempt exploitation for Critical/High
        exploitable = [
            v for v in self.state.approved_vulns if v.severity.lower() in ("critical", "high")
        ]

        if not exploitable:
            console.print("  ℹ️  No Critical/High findings to exploit.")
            return

        for vuln in exploitable:
            console.print(f"\n  🎯 Targeting: [bold]{vuln.vulnerability_id}[/bold] — {vuln.title}")

            # Retrieve memory hints for planner (Co-RedTeam §3.3 grounding phase)
            planner_memory_hints: list[str] = []
            if self.memory:
                cwe_items = self.memory.query_by_cwe(vuln.cwe_class)
                planner_memory_hints = [
                    f"{type(item).__name__}: "
                    f"{getattr(item, 'pattern_name', getattr(item, 'strategy_name', getattr(item, 'action_name', '')))}"
                    for item in cwe_items
                ]

            # Create exploit plan
            plan = await self.planner_agent.create_plan(
                vulnerability_description=vuln.model_dump_json(indent=2),
                code_context=self.state.code_context[:5000],
                memory_hints=planner_memory_hints if planner_memory_hints else None,
            )

            if not plan.steps:
                console.print("    ⚠️  Planner couldn't create a valid plan")
                continue

            console.print(f"    📋 Plan: {len(plan.steps)} steps")

            # Plan → Validate → Execute → Evaluate loop (Co-RedTeam §3.3)
            while plan.current_step and plan.has_budget:
                step = plan.current_step
                console.print(f"    → Step {step.step_id}: {step.goal}")

                if step.command:
                    # Validate before execution (Co-RedTeam §3.3)
                    validation = await self.validator_agent.validate_command(
                        command=step.command,
                        goal=step.goal,
                        exploit_context=f"{plan.target_cwe} — {plan.objective}",
                    )

                    if not validation.is_valid or not validation.is_safe:
                        console.print(
                            f"      ⚠️ Validation failed: {validation.explanation[:80]}"
                        )
                        plan.mark_blocked(step.step_id, reason=f"Validation: {validation.explanation}")
                        plan.iteration_count += 1
                        continue

                    # Use sanitized command if available
                    exec_command = validation.sanitized_command or step.command

                    # Execute in sandbox
                    result = await self.executor_agent.execute_command(exec_command)

                    # Evaluate
                    evaluation = await self.evaluator_agent.evaluate(
                        goal=step.goal,
                        execution_result=result,
                    )

                    if evaluation.goal_achieved:
                        plan.mark_done(step.step_id, output=result.stdout[:500])
                        console.print("      ✅ Achieved")
                    else:
                        plan.mark_blocked(step.step_id, reason=evaluation.explanation)
                        console.print(f"      ❌ Blocked: {evaluation.explanation[:80]}")

                        if evaluation.should_continue:
                            # Revise plan
                            plan = await self.planner_agent.revise_plan(
                                current_plan=plan,
                                execution_feedback=result.stdout[:2000],
                                evaluation_notes=evaluation.explanation,
                            )
                else:
                    plan.mark_done(step.step_id)

                plan.iteration_count += 1

            self.state.exploit_plans.append(plan)

            status = "✅ Exploited" if plan.is_complete else "⏸️ Partial"
            console.print(f"    {status} ({plan.iteration_count} iterations)")

    async def _phase_patching(self) -> None:
        """Phase 4: Patching — RCA → Generate → Validate loop."""
        console.print("\n[bold cyan]⟐ Phase 4: Security Patching[/bold cyan]")

        for vuln in self.state.approved_vulns:
            console.print(f"\n  🔧 Patching: {vuln.vulnerability_id} — {vuln.title}")

            # Root Cause Analysis
            rca = await self.patcher_agent.analyze_root_cause(
                vulnerability_description=vuln.model_dump_json(indent=2),
                code_context=self.state.code_context[:5000],
            )
            console.print(f"    📍 RCA: {rca.root_cause_description[:80]}")

            # Generate patch with reflection loop
            failed_patches: list[str] = []
            patch: PatchCandidate | None = None

            for attempt in range(self.config.patch.max_retry_attempts):
                patch = await self.patcher_agent.generate_patch(
                    rca=rca,
                    code_context=self.state.code_context[:5000],
                    prior_failed_patches=failed_patches if failed_patches else None,
                )

                if patch.confidence >= 0.5 and patch.patched_code:
                    console.print(
                        f"    ✅ Patch generated (attempt {attempt + 1}, "
                        f"confidence: {patch.confidence:.0%})"
                    )
                    self.state.patches.append(patch)
                    break
                failed_patches.append(
                    f"Attempt {attempt + 1}: {patch.fix_description} "
                    f"(confidence: {patch.confidence:.0%})"
                )
                console.print(f"    🔄 Attempt {attempt + 1} failed, reflecting...")
            else:
                console.print(
                    f"    ❌ Patching failed after {self.config.patch.max_retry_attempts} attempts"
                )

    async def _phase_reporting(self, target: Path) -> dict[str, str]:
        """Phase 5: Generate reports."""
        console.print("\n[bold cyan]⟐ Phase 5: Reporting[/bold cyan]")

        output_dir = self.config.report.output_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        report_paths: dict[str, str] = {}

        # Markdown report
        if self.config.report.generate_markdown:
            md_path = output_dir / "assessment_report.md"
            self.md_reporter.generate(
                target_name=str(target),
                vulnerabilities=self.state.approved_vulns,
                critiques=self.state.critiques,
                patches=self.state.patches,
                scan_duration_seconds=self.state.duration_seconds,
                output_path=md_path,
            )
            report_paths["markdown"] = str(md_path)
            console.print(f"  📄 Markdown: [green]{md_path}[/green]")

        # SARIF report
        if self.config.report.generate_sarif:
            sarif_path = output_dir / "findings.sarif"
            self.sarif_gen.generate(
                vulnerabilities=self.state.approved_vulns,
                patches=self.state.patches,
                output_path=sarif_path,
            )
            report_paths["sarif"] = str(sarif_path)
            console.print(f"  📄 SARIF: [green]{sarif_path}[/green]")

        return report_paths

    async def _phase_memory(self) -> None:
        """Phase 6: Store experience in 3-layer long-term memory (Co-RedTeam §3.4)."""
        if not self.memory:
            return

        console.print("\n[bold cyan]⟐ Phase 6: Memory Accumulation[/bold cyan]")

        # Layer 1: Vulnerability Patterns — from approved findings
        for vuln in self.state.approved_vulns:
            self.memory.store_pattern(
                cwe_class=vuln.cwe_class,
                pattern_name=vuln.title,
                symptom=vuln.description[:200],
                hypothesis=vuln.exploit_hypothesis,
                confirming_test=vuln.sink_operation,
                confidence=vuln.confidence,
                tech_stack=[self.state.tech_stack],
                source_assessment=f"scan-{int(self.state.start_time)}",
            )

        # Layer 2: Strategies — abstracted from completed Exploit Plans
        for plan in self.state.exploit_plans:
            completed_steps = sum(1 for s in plan.steps if s.status.value == "done")
            total_steps = len(plan.steps)
            outcome = (
                f"Completed {completed_steps}/{total_steps} steps in {plan.iteration_count} iterations"
            )
            self.memory.store_strategy(
                strategy_name=f"Exploit plan for {plan.target_cwe}: {plan.objective[:60]}",
                vulnerability_class=plan.target_cwe,
                approach="\n".join(
                    f"Step {s.step_id}: {s.action} → {s.goal}" for s in plan.steps[:8]
                ),
                applicable_when=f"Targeting {plan.target_cwe} vulnerabilities",
                successful_outcome=outcome if plan.is_complete else "",
                failure_case=(
                    {
                        "reason": next(
                            (s.failure_reason for s in plan.steps if s.failure_reason), "Unknown"
                        ),
                        "context": plan.objective,
                    }
                    if not plan.is_complete
                    else None
                ),
                transferable_to=[plan.target_cwe],
            )

        # Layer 3: Technical Actions — from execution logs
        for plan in self.state.exploit_plans:
            for step in plan.steps:
                if step.status.value == "done" and step.command:
                    self.memory.store_action(
                        action_name=f"{step.goal} ({plan.target_cwe})",
                        success_snippet=step.command,
                        prerequisites=[f"Target: {plan.target_cwe}"],
                        related_pattern=plan.vulnerability_id,
                    )
                elif step.status.value == "blocked" and step.command:
                    self.memory.store_action(
                        action_name=f"[FAILED] {step.goal} ({plan.target_cwe})",
                        success_snippet="",
                        failure_pitfall={
                            "command": step.command,
                            "reason": step.failure_reason[:200],
                        },
                        prerequisites=[f"Target: {plan.target_cwe}"],
                        related_pattern=plan.vulnerability_id,
                    )

        stats = self.memory.get_stats()
        console.print(
            f"  🧠 Memory: {stats['patterns']} patterns, "
            f"{stats['strategies']} strategies, {stats['actions']} actions"
        )

    def _print_summary(self) -> None:
        """Print final assessment summary."""
        table = Table(title="Assessment Summary", border_style="red")
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")

        table.add_row("Duration", f"{self.state.duration_seconds:.1f}s")
        table.add_row("Files Scanned", str(self.state.files_scanned))
        table.add_row("Vulnerabilities Found", str(len(self.state.approved_vulns)))
        table.add_row("Exploit Plans", str(len(self.state.exploit_plans)))
        table.add_row("Patches Generated", str(len(self.state.patches)))

        # Severity breakdown
        for sev in ("Critical", "High", "Medium", "Low"):
            count = sum(1 for v in self.state.approved_vulns if v.severity.lower() == sev.lower())
            if count > 0:
                table.add_row(f"  {sev}", str(count))

        console.print()
        console.print(table)
        console.print()

    # --- Helper Methods ---

    def _build_file_tree(self, target: Path, max_depth: int = 4) -> str:
        """Build a text representation of the file tree."""
        lines: list[str] = []
        self._walk_tree(target, lines, prefix="", depth=0, max_depth=max_depth)
        return "\n".join(lines[:200])  # Cap output

    def _walk_tree(
        self,
        path: Path,
        lines: list[str],
        prefix: str,
        depth: int,
        max_depth: int,
    ) -> None:
        """Recursively walk the file tree."""
        if depth > max_depth:
            return

        try:
            entries = sorted(path.iterdir(), key=lambda e: (not e.is_dir(), e.name.lower()))
        except PermissionError:
            return

        excluded = set(self.config.exclude_patterns)

        for entry in entries:
            # Check against exclude patterns (support simple names and glob-style)
            entry_name = entry.name
            if entry_name.startswith("."):
                continue
            if entry_name in excluded:
                continue
            # Handle glob patterns like *.egg-info
            skip = False
            for pattern in excluded:
                if "*" in pattern and fnmatch.fnmatch(entry_name, pattern):
                    skip = True
                    break
            if skip:
                continue

            lines.append(f"{prefix}{entry.name}")

            if entry.is_dir():
                self._walk_tree(
                    entry, lines, prefix=prefix + "  ", depth=depth + 1, max_depth=max_depth
                )

    def _detect_tech_stack(self, target: Path) -> str:
        """Detect the project's technology stack."""
        indicators: list[str] = []

        manifest_map = {
            "package.json": "Node.js/JavaScript",
            "requirements.txt": "Python",
            "Pipfile": "Python",
            "pyproject.toml": "Python",
            "Cargo.toml": "Rust",
            "go.mod": "Go",
            "pom.xml": "Java/Maven",
            "build.gradle": "Java/Gradle",
            "Gemfile": "Ruby",
            "composer.json": "PHP",
        }

        framework_map = {
            "manage.py": "Django",
            "wsgi.py": "WSGI",
            "next.config": "Next.js",
            "nuxt.config": "Nuxt.js",
            "angular.json": "Angular",
            "vite.config": "Vite",
        }

        for name, tech in manifest_map.items():
            if (target / name).exists():
                indicators.append(tech)

        for name, framework in framework_map.items():
            matches = list(target.rglob(f"{name}*"))
            if matches:
                indicators.append(framework)

        if not indicators:
            # Fallback: check file extensions
            extensions = set()
            for file in target.rglob("*"):
                if file.is_file() and file.suffix:
                    extensions.add(file.suffix)

            ext_map = {
                ".py": "Python",
                ".js": "JavaScript",
                ".ts": "TypeScript",
                ".java": "Java",
                ".go": "Go",
                ".rs": "Rust",
                ".rb": "Ruby",
                ".php": "PHP",
                ".c": "C",
                ".cpp": "C++",
            }
            for ext, lang in ext_map.items():
                if ext in extensions:
                    indicators.append(lang)

        return ", ".join(sorted(set(indicators))) or "Unknown"

    def _read_source_files(self, target: Path) -> str:
        """Read source files into a single context string."""
        code_extensions = {
            ".py",
            ".js",
            ".ts",
            ".jsx",
            ".tsx",
            ".java",
            ".go",
            ".rs",
            ".rb",
            ".php",
            ".c",
            ".cpp",
            ".h",
            ".cs",
        }

        excluded = set(self.config.exclude_patterns)
        files_content: list[str] = []
        total_chars = 0
        max_chars = 200_000  # ~50k tokens

        for file_path in sorted(target.rglob("*")):
            if not file_path.is_file():
                continue
            if file_path.suffix not in code_extensions:
                continue
            if any(
                excluded_dir in file_path.parts
                or any(
                    fnmatch.fnmatch(part, excluded_dir) for part in file_path.parts
                )
                for excluded_dir in excluded
            ):
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                header = f"\n{'=' * 60}\n# FILE: {file_path.relative_to(target)}\n{'=' * 60}\n"
                file_text = header + content

                if total_chars + len(file_text) > max_chars:
                    break

                files_content.append(file_text)
                total_chars += len(file_text)
                self.state.files_scanned += 1

            except (PermissionError, UnicodeDecodeError, OSError):
                continue

        return "\n".join(files_content)
