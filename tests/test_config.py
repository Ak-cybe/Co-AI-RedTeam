"""Tests for the configuration system."""

import tempfile
from pathlib import Path

import pytest

from co_redteam.config import (
    DiscoveryConfig,
    LLMConfig,
    LLMProvider,
    MemoryConfig,
    RedTeamConfig,
    ScanScope,
    SeverityLevel,
)


class TestLLMConfig:
    """Test LLM configuration."""

    def test_default_provider(self) -> None:
        config = LLMConfig()
        assert config.provider == LLMProvider.GEMINI
        assert config.model == "gemini-2.5-pro"

    def test_temperature_bounds(self) -> None:
        config = LLMConfig(temperature=0.5)
        assert config.temperature == 0.5

        with pytest.raises(ValueError):
            LLMConfig(temperature=-0.1)

        with pytest.raises(ValueError):
            LLMConfig(temperature=2.5)

    def test_max_tokens_bounds(self) -> None:
        config = LLMConfig(max_tokens=4096)
        assert config.max_tokens == 4096

        with pytest.raises(ValueError):
            LLMConfig(max_tokens=100)  # Below 256


class TestRedTeamConfig:
    """Test master configuration."""

    def test_default_config(self) -> None:
        config = RedTeamConfig()
        assert config.scope == ScanScope.FULL
        assert config.discovery.max_critique_iterations == 3
        assert config.exploit.max_iterations == 20
        assert config.patch.max_retry_attempts == 5
        assert config.memory.enabled is True

    def test_exclude_patterns(self) -> None:
        config = RedTeamConfig()
        assert "node_modules" in config.exclude_patterns
        assert ".git" in config.exclude_patterns

    def test_yaml_roundtrip(self) -> None:
        """Config should survive YAML serialization."""
        config = RedTeamConfig(
            scope=ScanScope.DIRECTORY,
            discovery=DiscoveryConfig(max_critique_iterations=5),
        )

        with tempfile.NamedTemporaryFile(suffix=".yml", delete=False, mode="w") as tmp:
            tmp_path = Path(tmp.name)

        try:
            config.to_file(tmp_path)
            loaded = RedTeamConfig.from_file(tmp_path)

            assert loaded.scope == ScanScope.DIRECTORY
            assert loaded.discovery.max_critique_iterations == 5
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_severity_levels(self) -> None:
        config = RedTeamConfig()
        config.discovery.min_severity = SeverityLevel.HIGH
        assert config.discovery.min_severity == SeverityLevel.HIGH


class TestDiscoveryConfig:
    """Test discovery stage configuration."""

    def test_confidence_bounds(self) -> None:
        config = DiscoveryConfig(min_confidence=0.8)
        assert config.min_confidence == 0.8

        with pytest.raises(ValueError):
            DiscoveryConfig(min_confidence=1.5)

    def test_critique_iterations(self) -> None:
        config = DiscoveryConfig(max_critique_iterations=7)
        assert config.max_critique_iterations == 7


class TestMemoryConfig:
    """Test memory configuration."""

    def test_default_values(self) -> None:
        config = MemoryConfig()
        assert config.enabled is True
        assert config.max_patterns == 500
        assert config.similarity_threshold == 0.75
        assert config.top_k_retrieval == 3
