"""
Memory Store — Persistent storage and retrieval for security experience.

Implements the Co-RedTeam 3-layer memory system with JSON-based persistence,
keyword-based similarity search, and automatic ID generation.
"""

from __future__ import annotations

import json
from pathlib import Path

from co_redteam.memory.schemas import (
    Strategy,
    TechnicalAction,
    VulnerabilityPattern,
)

MemoryItem = VulnerabilityPattern | Strategy | TechnicalAction


class MemoryStore:
    """
    Persistent memory store for security experience.

    Organizes items into three layers:
    - patterns/  → VulnerabilityPattern items
    - strategies/ → Strategy items
    - actions/   → TechnicalAction items
    """

    LAYER_DIRS = {
        "vulnerability_pattern": "patterns",
        "strategy": "strategies",
        "technical_action": "actions",
    }

    def __init__(self, storage_dir: Path) -> None:
        self.storage_dir = storage_dir
        self._ensure_directories()
        self._counters: dict[str, int] = {}
        self._load_counters()

    def _ensure_directories(self) -> None:
        """Create storage directories if they don't exist."""
        for subdir in self.LAYER_DIRS.values():
            (self.storage_dir / subdir).mkdir(parents=True, exist_ok=True)

    def _load_counters(self) -> None:
        """Count existing items to set ID counters."""
        for item_type, subdir in self.LAYER_DIRS.items():
            path = self.storage_dir / subdir
            existing = list(path.glob("*.json"))
            prefix = {"vulnerability_pattern": "VP", "strategy": "ST", "technical_action": "TA"}
            self._counters[prefix[item_type]] = len(existing)

    def _next_id(self, prefix: str) -> str:
        """Generate the next sequential ID."""
        self._counters[prefix] = self._counters.get(prefix, 0) + 1
        return f"{prefix}-{self._counters[prefix]:03d}"

    def store(self, item: MemoryItem) -> str:
        """
        Store a memory item persistently.

        Returns:
            The item ID.
        """
        subdir = self.LAYER_DIRS.get(item.type, "patterns")
        file_path = self.storage_dir / subdir / f"{item.id}.json"
        file_path.write_text(
            item.model_dump_json(indent=2),
            encoding="utf-8",
        )
        return item.id

    def store_pattern(
        self,
        cwe_class: str,
        pattern_name: str,
        symptom: str,
        hypothesis: str,
        confirming_test: str,
        confidence: float,
        tech_stack: list[str] | None = None,
        false_leads: list[str] | None = None,
        source_assessment: str = "",
    ) -> VulnerabilityPattern:
        """Create and store a vulnerability pattern."""
        pattern = VulnerabilityPattern(
            id=self._next_id("VP"),
            cwe_class=cwe_class,
            pattern_name=pattern_name,
            symptom=symptom,
            hypothesis=hypothesis,
            confirming_test=confirming_test,
            confidence=confidence,
            tech_stack=tech_stack or [],
            false_leads=false_leads or [],
            source_assessment=source_assessment,
        )
        self.store(pattern)
        return pattern

    def store_strategy(
        self,
        strategy_name: str,
        vulnerability_class: str,
        approach: str,
        applicable_when: str = "",
        successful_outcome: str = "",
        failure_case: dict[str, str] | None = None,
        transferable_to: list[str] | None = None,
    ) -> Strategy:
        """Create and store a strategy."""
        strategy = Strategy(
            id=self._next_id("ST"),
            strategy_name=strategy_name,
            vulnerability_class=vulnerability_class,
            approach=approach,
            applicable_when=applicable_when,
            successful_outcome=successful_outcome,
            failure_case=failure_case,
            transferable_to=transferable_to or [],
        )
        self.store(strategy)
        return strategy

    def store_action(
        self,
        action_name: str,
        success_snippet: str = "",
        failure_pitfall: dict[str, str] | None = None,
        prerequisites: list[str] | None = None,
        related_pattern: str = "",
    ) -> TechnicalAction:
        """Create and store a technical action."""
        action = TechnicalAction(
            id=self._next_id("TA"),
            action_name=action_name,
            success_snippet=success_snippet,
            failure_pitfall=failure_pitfall,
            prerequisites=prerequisites or [],
            related_pattern=related_pattern,
        )
        self.store(action)
        return action

    def query_by_cwe(self, cwe_id: str, top_k: int = 3) -> list[MemoryItem]:
        """
        Retrieve memory items matching a CWE class.

        Args:
            cwe_id: CWE identifier (e.g., "CWE-89").
            top_k: Maximum items to return.

        Returns:
            List of matching memory items, sorted by confidence.
        """
        results: list[MemoryItem] = []
        cwe_normalized = cwe_id.upper()

        # Search patterns
        for item in self._load_all("patterns", VulnerabilityPattern):
            if cwe_normalized in item.cwe_class.upper():
                results.append(item)

        # Search strategies
        for item in self._load_all("strategies", Strategy):
            if cwe_normalized in item.vulnerability_class.upper() or any(
                cwe_normalized in t.upper() for t in item.transferable_to
            ):
                results.append(item)

        # Sort by confidence (patterns) or timestamp
        results.sort(key=lambda x: getattr(x, "confidence", 0.5), reverse=True)

        return results[:top_k]

    def query_by_tech_stack(self, tech: str, top_k: int = 3) -> list[MemoryItem]:
        """Retrieve items matching a technology stack component."""
        results: list[MemoryItem] = []
        tech_lower = tech.lower()

        for item in self._load_all("patterns", VulnerabilityPattern):
            if any(tech_lower in t.lower() for t in item.tech_stack):
                results.append(item)

        return results[:top_k]

    def get_all_patterns(self) -> list[VulnerabilityPattern]:
        """Return all stored vulnerability patterns."""
        return list(self._load_all("patterns", VulnerabilityPattern))

    def get_all_strategies(self) -> list[Strategy]:
        """Return all stored strategies."""
        return list(self._load_all("strategies", Strategy))

    def get_all_actions(self) -> list[TechnicalAction]:
        """Return all stored technical actions."""
        return list(self._load_all("actions", TechnicalAction))

    def get_stats(self) -> dict[str, int]:
        """Return item counts per layer."""
        return {
            "patterns": len(list((self.storage_dir / "patterns").glob("*.json"))),
            "strategies": len(list((self.storage_dir / "strategies").glob("*.json"))),
            "actions": len(list((self.storage_dir / "actions").glob("*.json"))),
        }

    def _load_all(self, subdir: str, model_class: type) -> list:
        """Load all items from a subdirectory."""
        path = self.storage_dir / subdir
        items = []
        for file_path in sorted(path.glob("*.json")):
            try:
                data = json.loads(file_path.read_text(encoding="utf-8"))
                items.append(model_class.model_validate(data))
            except (json.JSONDecodeError, ValueError):
                continue
        return items
