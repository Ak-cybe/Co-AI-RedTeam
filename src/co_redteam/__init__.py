"""
Co-AI-RedTeam: Multi-agent AI framework for automated red teaming.

Orchestrates vulnerability discovery, exploitation, and patching
using coordinated LLM agents with execution-grounded reasoning.
"""

__version__ = "0.1.0"
__author__ = "Co-AI-RedTeam Contributors"

from co_redteam.config import RedTeamConfig
from co_redteam.orchestrator import Orchestrator

__all__ = ["Orchestrator", "RedTeamConfig", "__version__"]
