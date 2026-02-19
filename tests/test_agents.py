"""Tests for agent base classes and data models."""

from co_redteam.agents.base import (
    ROLE_TOOL_MAP,
    AgentRole,
    ToolPermission,
)
from co_redteam.agents.planner import ExploitPlan, ExploitStep, StepStatus


class TestAgentRoles:
    """Test role-aware tool assignment."""

    def test_analysis_tools(self) -> None:
        tools = ROLE_TOOL_MAP[AgentRole.ANALYSIS]
        assert ToolPermission.CODE_BROWSE in tools
        assert ToolPermission.VULN_DOCS in tools
        assert ToolPermission.MEMORY_READ in tools
        # Should NOT have execution or file editing
        assert ToolPermission.RUN_BASH not in tools
        assert ToolPermission.CODE_EDIT not in tools

    def test_executor_tools(self) -> None:
        tools = ROLE_TOOL_MAP[AgentRole.EXECUTOR]
        assert ToolPermission.RUN_BASH in tools
        assert ToolPermission.RUN_PYTHON in tools
        # Should NOT have code browsing
        assert ToolPermission.CODE_BROWSE not in tools

    def test_patcher_tools(self) -> None:
        tools = ROLE_TOOL_MAP[AgentRole.PATCHER]
        assert ToolPermission.CODE_EDIT in tools
        assert ToolPermission.BUILD in tools
        assert ToolPermission.TEST in tools
        # Should NOT have execution tools
        assert ToolPermission.RUN_BASH not in tools

    def test_critique_no_execution(self) -> None:
        """Critique agent should only have read access."""
        tools = ROLE_TOOL_MAP[AgentRole.CRITIQUE]
        assert ToolPermission.RUN_BASH not in tools
        assert ToolPermission.CODE_EDIT not in tools
        assert ToolPermission.MEMORY_WRITE not in tools

    def test_validator_limited(self) -> None:
        """Validator should only check syntax and safety."""
        tools = ROLE_TOOL_MAP[AgentRole.VALIDATOR]
        assert ToolPermission.SYNTAX_CHECK in tools
        assert ToolPermission.SAFETY_CHECK in tools
        assert len(tools) == 2

    def test_validator_no_execution(self) -> None:
        """Validator should NOT have execution or code edit tools."""
        tools = ROLE_TOOL_MAP[AgentRole.VALIDATOR]
        assert ToolPermission.RUN_BASH not in tools
        assert ToolPermission.RUN_PYTHON not in tools
        assert ToolPermission.CODE_EDIT not in tools
        assert ToolPermission.CODE_BROWSE not in tools


class TestExploitPlan:
    """Test exploit plan management."""

    def _make_plan(self) -> ExploitPlan:
        return ExploitPlan(
            vulnerability_id="VULN-001",
            target_cwe="CWE-89",
            objective="Dump user database",
            steps=[
                ExploitStep(step_id=1, goal="Identify injection point", action="Scan"),
                ExploitStep(step_id=2, goal="Craft payload", action="Generate"),
                ExploitStep(step_id=3, goal="Execute PoC", action="Run"),
            ],
        )

    def test_current_step(self) -> None:
        plan = self._make_plan()
        assert plan.current_step is not None
        assert plan.current_step.step_id == 1

    def test_mark_done_and_advance(self) -> None:
        plan = self._make_plan()
        plan.mark_done(1, output="Found injection at line 42")

        assert plan.steps[0].status == StepStatus.DONE
        assert plan.steps[0].output == "Found injection at line 42"
        assert plan.current_step is not None
        assert plan.current_step.step_id == 2

    def test_mark_blocked(self) -> None:
        plan = self._make_plan()
        plan.mark_blocked(1, reason="WAF detected")

        assert plan.steps[0].status == StepStatus.BLOCKED
        assert plan.steps[0].failure_reason == "WAF detected"

    def test_is_complete(self) -> None:
        plan = self._make_plan()
        assert not plan.is_complete

        for step in plan.steps:
            step.status = StepStatus.DONE
        assert plan.is_complete

    def test_has_budget(self) -> None:
        plan = self._make_plan()
        assert plan.has_budget

        plan.iteration_count = 20
        assert not plan.has_budget

    def test_insert_corrective_step(self) -> None:
        plan = self._make_plan()
        corrective = ExploitStep(step_id=10, goal="Bypass WAF", action="Evasion")
        plan.insert_corrective_step(after_step_id=1, new_step=corrective)

        assert len(plan.steps) == 4
        assert plan.steps[1].step_id == 10
        assert plan.steps[1].goal == "Bypass WAF"

    def test_advance_all_done_returns_none(self) -> None:
        """When all steps are done, current_step should return None."""
        plan = self._make_plan()
        for step in plan.steps:
            step.status = StepStatus.DONE
        plan.advance()
        assert plan.current_step is None

    def test_advance_all_blocked_returns_none(self) -> None:
        """When all remaining steps are blocked, current_step should return None."""
        plan = self._make_plan()
        plan.steps[0].status = StepStatus.DONE
        plan.steps[1].status = StepStatus.BLOCKED
        plan.steps[2].status = StepStatus.BLOCKED
        plan.advance()
        assert plan.current_step is None

    def test_mark_done_last_step_completes(self) -> None:
        """Marking the last step as done should make current_step None."""
        plan = self._make_plan()
        plan.mark_done(1)
        plan.mark_done(2)
        plan.mark_done(3)
        assert plan.current_step is None
        assert plan.is_complete

