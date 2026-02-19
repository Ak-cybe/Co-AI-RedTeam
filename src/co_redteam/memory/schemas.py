"""Memory data schemas — Co-RedTeam 3-layer memory model."""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field


class VulnerabilityPattern(BaseModel):
    """Layer 1: Confirmed vulnerability templates."""

    type: str = "vulnerability_pattern"
    id: str
    cwe_class: str
    pattern_name: str
    symptom: str
    hypothesis: str
    confirming_test: str
    false_leads: list[str] = Field(default_factory=list)
    tech_stack: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    source_assessment: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Strategy(BaseModel):
    """Layer 2: High-level exploitation workflows."""

    type: str = "strategy"
    id: str
    strategy_name: str
    vulnerability_class: str
    approach: str
    applicable_when: str = ""
    successful_outcome: str = ""
    failure_case: dict[str, str] | None = None
    transferable_to: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class TechnicalAction(BaseModel):
    """Layer 3: Concrete commands and reusable snippets."""

    type: str = "technical_action"
    id: str
    action_name: str
    success_snippet: str = ""
    failure_pitfall: dict[str, str] | None = None
    prerequisites: list[str] = Field(default_factory=list)
    related_pattern: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
