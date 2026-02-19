"""Tests for the memory store."""

import json
import tempfile
from pathlib import Path

import pytest

from co_redteam.memory.store import MemoryStore


@pytest.fixture
def memory_dir() -> Path:
    """Create a temporary directory for memory tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def store(memory_dir: Path) -> MemoryStore:
    """Create a fresh MemoryStore."""
    return MemoryStore(memory_dir)


class TestMemoryStore:
    """Test the 3-layer memory store."""

    def test_directory_creation(self, memory_dir: Path) -> None:
        """Store should create required directories."""
        MemoryStore(memory_dir)
        assert (memory_dir / "patterns").is_dir()
        assert (memory_dir / "strategies").is_dir()
        assert (memory_dir / "actions").is_dir()

    def test_store_pattern(self, store: MemoryStore) -> None:
        """Should store and retrieve vulnerability patterns."""
        pattern = store.store_pattern(
            cwe_class="CWE-89",
            pattern_name="SQL Injection via f-string",
            symptom="F-string interpolation in SQL query",
            hypothesis="User input injected directly into SQL",
            confirming_test="cursor.execute(f'SELECT ... {user_input}')",
            confidence=0.95,
            tech_stack=["Python", "SQLite"],
        )

        assert pattern.id == "VP-001"
        assert pattern.cwe_class == "CWE-89"
        assert pattern.confidence == 0.95

        # Verify file was written
        file_path = store.storage_dir / "patterns" / "VP-001.json"
        assert file_path.exists()

        # Verify JSON is valid
        data = json.loads(file_path.read_text())
        assert data["cwe_class"] == "CWE-89"

    def test_store_strategy(self, store: MemoryStore) -> None:
        """Should store and retrieve strategies."""
        strategy = store.store_strategy(
            strategy_name="Config-first SSRF analysis",
            vulnerability_class="CWE-918",
            approach="Map config before payloads",
            applicable_when="Web app with configurable HTTP client",
            successful_outcome="Found SSRF in 2/3 targets",
        )

        assert strategy.id == "ST-001"
        assert strategy.vulnerability_class == "CWE-918"

    def test_store_action(self, store: MemoryStore) -> None:
        """Should store and retrieve technical actions."""
        action = store.store_action(
            action_name="Test SSRF to cloud metadata",
            success_snippet="curl http://target?url=http://169.254.169.254/",
            prerequisites=["Docker environment", "No URL allowlist"],
        )

        assert action.id == "TA-001"
        assert "curl" in action.success_snippet

    def test_auto_incrementing_ids(self, store: MemoryStore) -> None:
        """IDs should auto-increment."""
        p1 = store.store_pattern(
            cwe_class="CWE-79",
            pattern_name="XSS",
            symptom="s",
            hypothesis="h",
            confirming_test="t",
            confidence=0.5,
        )
        p2 = store.store_pattern(
            cwe_class="CWE-89",
            pattern_name="SQLi",
            symptom="s",
            hypothesis="h",
            confirming_test="t",
            confidence=0.8,
        )

        assert p1.id == "VP-001"
        assert p2.id == "VP-002"

    def test_query_by_cwe(self, store: MemoryStore) -> None:
        """Should retrieve items matching a CWE ID."""
        store.store_pattern(
            cwe_class="CWE-89: SQL Injection",
            pattern_name="SQLi via f-string",
            symptom="s",
            hypothesis="h",
            confirming_test="t",
            confidence=0.9,
        )
        store.store_pattern(
            cwe_class="CWE-79: XSS",
            pattern_name="XSS via innerHTML",
            symptom="s",
            hypothesis="h",
            confirming_test="t",
            confidence=0.8,
        )
        store.store_strategy(
            strategy_name="SQLi strategy",
            vulnerability_class="CWE-89",
            approach="Check query construction",
        )

        results = store.query_by_cwe("CWE-89")
        assert len(results) == 2  # 1 pattern + 1 strategy

        # Should be sorted by confidence
        assert results[0].id == "VP-001"

    def test_query_empty_store(self, store: MemoryStore) -> None:
        """Query on empty store should return empty list."""
        results = store.query_by_cwe("CWE-89")
        assert results == []

    def test_get_stats(self, store: MemoryStore) -> None:
        """Should return correct counts."""
        store.store_pattern(
            cwe_class="CWE-89",
            pattern_name="p1",
            symptom="s",
            hypothesis="h",
            confirming_test="t",
            confidence=0.9,
        )
        store.store_strategy(
            strategy_name="s1",
            vulnerability_class="CWE-89",
            approach="a",
        )
        store.store_action(action_name="a1")

        stats = store.get_stats()
        assert stats["patterns"] == 1
        assert stats["strategies"] == 1
        assert stats["actions"] == 1

    def test_get_all_patterns(self, store: MemoryStore) -> None:
        """Should retrieve all stored patterns."""
        for i in range(3):
            store.store_pattern(
                cwe_class=f"CWE-{89 + i}",
                pattern_name=f"Pattern {i}",
                symptom="s",
                hypothesis="h",
                confirming_test="t",
                confidence=0.5 + i * 0.1,
            )

        patterns = store.get_all_patterns()
        assert len(patterns) == 3

    def test_persistence(self, memory_dir: Path) -> None:
        """Data should persist across MemoryStore instances."""
        store1 = MemoryStore(memory_dir)
        store1.store_pattern(
            cwe_class="CWE-89",
            pattern_name="Persistent",
            symptom="s",
            hypothesis="h",
            confirming_test="t",
            confidence=0.9,
        )

        # Create new store instance
        store2 = MemoryStore(memory_dir)
        patterns = store2.get_all_patterns()
        assert len(patterns) == 1
        assert patterns[0].pattern_name == "Persistent"
