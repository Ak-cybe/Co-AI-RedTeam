"""Configuration management for Co-AI-RedTeam."""

from __future__ import annotations

import os
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field, SecretStr

# Auto-load .env file if present (fail silently if python-dotenv not installed)
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass


class LLMProvider(str, Enum):
    """Supported LLM providers."""

    GEMINI = "gemini"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"


class ScanScope(str, Enum):
    """Scope of the security scan."""

    FULL = "full"
    DELTA = "delta"
    FILE = "file"
    DIRECTORY = "directory"


class SeverityLevel(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class LLMConfig(BaseModel):
    """LLM provider configuration."""

    provider: LLMProvider = LLMProvider.GEMINI
    model: str = "gemini-2.5-pro"
    api_key: SecretStr | None = Field(default=None)
    temperature: float = Field(default=0.1, ge=0.0, le=2.0)
    max_tokens: int = Field(default=8192, ge=256, le=65536)
    embedding_model: str = "text-embedding-004"

    def resolve_api_key(self) -> str:
        """Resolve API key from config or environment."""
        if self.api_key:
            return self.api_key.get_secret_value()

        env_map = {
            LLMProvider.GEMINI: "GEMINI_API_KEY",
            LLMProvider.OPENAI: "OPENAI_API_KEY",
            LLMProvider.ANTHROPIC: "ANTHROPIC_API_KEY",
            LLMProvider.OLLAMA: "",
        }
        env_var = env_map.get(self.provider, "")
        if env_var:
            key = os.environ.get(env_var, "")
            if not key:
                raise ValueError(
                    f"API key not found. Set {env_var} environment variable or pass --api-key flag."
                )
            return key
        return ""


class SandboxConfig(BaseModel):
    """Docker sandbox configuration."""

    enabled: bool = True
    image: str = "python:3.12-slim"
    timeout_seconds: int = Field(default=60, ge=5, le=600)
    memory_limit: str = "512m"
    network_disabled: bool = False
    remove_after: bool = True


class DiscoveryConfig(BaseModel):
    """Vulnerability discovery stage configuration."""

    max_critique_iterations: int = Field(default=3, ge=1, le=10)
    min_confidence: float = Field(default=0.6, ge=0.0, le=1.0)
    min_severity: SeverityLevel = SeverityLevel.LOW
    include_informational: bool = False
    max_files_per_scan: int = Field(default=500, ge=1, le=5000)


class ExploitConfig(BaseModel):
    """Exploitation stage configuration."""

    enabled: bool = True
    max_iterations: int = Field(default=20, ge=1, le=50)
    require_validation: bool = True
    sandbox_execution: bool = True
    generate_poc: bool = True


class PatchConfig(BaseModel):
    """Patching stage configuration."""

    enabled: bool = True
    max_retry_attempts: int = Field(default=5, ge=1, le=10)
    run_build_check: bool = True
    run_test_suite: bool = True
    run_pov_test: bool = True
    minimal_diff: bool = True


class MemoryConfig(BaseModel):
    """Long-term memory configuration."""

    enabled: bool = True
    storage_dir: Path = Path(".cart_memory")
    max_patterns: int = 500
    max_strategies: int = 200
    max_actions: int = 1000
    similarity_threshold: float = Field(default=0.75, ge=0.0, le=1.0)
    top_k_retrieval: int = Field(default=3, ge=1, le=10)


class ReportConfig(BaseModel):
    """Report generation configuration."""

    output_dir: Path = Path("reports")
    generate_sarif: bool = True
    generate_markdown: bool = True
    generate_html: bool = False
    include_poc_code: bool = True
    include_patches: bool = True


class RedTeamConfig(BaseModel):
    """Master configuration for Co-AI-RedTeam."""

    target_path: Path = Path(".")
    scope: ScanScope = ScanScope.FULL
    vulnerability_hint: str | None = None
    exclude_patterns: list[str] = Field(
        default_factory=lambda: [
            "node_modules",
            ".git",
            "__pycache__",
            ".venv",
            "venv",
            "dist",
            "build",
            ".eggs",
            "*.egg-info",
        ]
    )

    llm: LLMConfig = Field(default_factory=LLMConfig)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    discovery: DiscoveryConfig = Field(default_factory=DiscoveryConfig)
    exploit: ExploitConfig = Field(default_factory=ExploitConfig)
    patch: PatchConfig = Field(default_factory=PatchConfig)
    memory: MemoryConfig = Field(default_factory=MemoryConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)

    verbose: bool = False
    debug: bool = False

    @classmethod
    def from_file(cls, config_path: Path) -> RedTeamConfig:
        """Load configuration from YAML file."""
        import yaml

        with open(config_path) as fh:
            raw = yaml.safe_load(fh)
        return cls.model_validate(raw or {})

    def to_file(self, config_path: Path) -> None:
        """Save configuration to YAML file."""
        import yaml

        config_path.parent.mkdir(parents=True, exist_ok=True)
        data = self.model_dump(mode="json", exclude_none=True)
        with open(config_path, "w") as fh:
            yaml.dump(data, fh, default_flow_style=False, sort_keys=False)
