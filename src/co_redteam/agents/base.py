"""Base agent class for all Co-AI-RedTeam agents."""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from co_redteam.config import LLMConfig


class AgentRole(str, Enum):
    """Agent roles in the red team pipeline."""

    ANALYSIS = "analysis"
    CRITIQUE = "critique"
    PLANNER = "planner"
    VALIDATOR = "validator"
    EXECUTOR = "executor"
    EVALUATOR = "evaluator"
    PATCHER = "patcher"


class ToolPermission(str, Enum):
    """Tools that can be assigned to agents."""

    CODE_BROWSE = "code_browse"
    VULN_DOCS = "vuln_docs"
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"
    RUN_BASH = "run_bash"
    RUN_PYTHON = "run_python"
    CODE_EDIT = "code_edit"
    BUILD = "build"
    TEST = "test"
    SYNTAX_CHECK = "syntax_check"
    SAFETY_CHECK = "safety_check"


# Role-aware tool assignment — principle of least privilege
ROLE_TOOL_MAP: dict[AgentRole, set[ToolPermission]] = {
    AgentRole.ANALYSIS: {
        ToolPermission.CODE_BROWSE,
        ToolPermission.VULN_DOCS,
        ToolPermission.MEMORY_READ,
    },
    AgentRole.CRITIQUE: {
        ToolPermission.CODE_BROWSE,
        ToolPermission.VULN_DOCS,
    },
    AgentRole.PLANNER: {
        ToolPermission.VULN_DOCS,
        ToolPermission.MEMORY_READ,
        ToolPermission.CODE_BROWSE,
    },
    AgentRole.VALIDATOR: {
        ToolPermission.SYNTAX_CHECK,
        ToolPermission.SAFETY_CHECK,
    },
    AgentRole.EXECUTOR: {
        ToolPermission.RUN_BASH,
        ToolPermission.RUN_PYTHON,
    },
    AgentRole.EVALUATOR: {
        ToolPermission.SYNTAX_CHECK,
    },
    AgentRole.PATCHER: {
        ToolPermission.CODE_EDIT,
        ToolPermission.BUILD,
        ToolPermission.TEST,
        ToolPermission.CODE_BROWSE,
    },
}


class AgentMessage(BaseModel):
    """Message exchanged between agents."""

    role: str
    content: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: float = Field(default_factory=time.time)


class AgentResponse(BaseModel):
    """Structured response from an agent."""

    agent_role: AgentRole
    content: str
    structured_output: dict[str, Any] | None = None
    tokens_used: int = 0
    latency_ms: float = 0.0
    success: bool = True
    error: str | None = None


class BaseAgent(ABC):
    """
    Abstract base class for all Co-AI-RedTeam agents.

    Each agent has:
    - A role that determines its tool permissions
    - A system prompt that defines its behavior
    - Access to an LLM provider for reasoning
    """

    def __init__(
        self,
        role: AgentRole,
        llm_config: LLMConfig,
        system_prompt: str = "",
    ) -> None:
        self.role = role
        self.llm_config = llm_config
        self.system_prompt = system_prompt
        self.permitted_tools = ROLE_TOOL_MAP.get(role, set())
        self.conversation_history: list[AgentMessage] = []
        self._llm_client: Any = None

    @property
    def name(self) -> str:
        """Human-readable agent name."""
        return f"{self.role.value.capitalize()}Agent"

    def has_permission(self, tool: ToolPermission) -> bool:
        """Check if this agent has permission to use a tool."""
        return tool in self.permitted_tools

    def _ensure_client(self) -> Any:
        """Lazily initialize the LLM client."""
        if self._llm_client is None:
            self._llm_client = self._create_client()
        return self._llm_client

    def _create_client(self) -> Any:
        """Create the LLM client based on provider configuration."""
        from co_redteam.config import LLMProvider

        provider = self.llm_config.provider
        api_key = self.llm_config.resolve_api_key()

        if provider == LLMProvider.GEMINI:
            from google import genai

            return genai.Client(api_key=api_key)
        if provider == LLMProvider.OPENAI:
            try:
                import openai

                return openai.AsyncOpenAI(api_key=api_key)
            except ImportError as exc:
                raise ImportError("Install openai: pip install openai") from exc
        elif provider == LLMProvider.ANTHROPIC:
            try:
                import anthropic

                return anthropic.AsyncAnthropic(api_key=api_key)
            except ImportError as exc:
                raise ImportError("Install anthropic: pip install anthropic") from exc
        else:
            raise ValueError(f"Unsupported provider: {provider}")

    async def _call_llm(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float | None = None,
    ) -> dict[str, Any]:
        """
        Unified LLM call that handles provider routing and async execution.

        Returns:
            Dict with 'content' (str) and 'tokens' (int).
        """
        import asyncio

        from co_redteam.config import LLMProvider

        client = self._ensure_client()
        provider = self.llm_config.provider
        sys_prompt = system_prompt or self.system_prompt
        temp = temperature if temperature is not None else self.llm_config.temperature

        try:
            if provider == LLMProvider.GEMINI:
                # google-genai is synchronous — run in thread pool to avoid blocking
                response = await asyncio.to_thread(
                    client.models.generate_content,
                    model=self.llm_config.model,
                    contents=[{"role": "user", "parts": [{"text": prompt}]}],
                    config={
                        "system_instruction": sys_prompt,
                        "temperature": temp,
                        "max_output_tokens": self.llm_config.max_tokens,
                    },
                )
                tokens = 0
                if hasattr(response, "usage_metadata") and response.usage_metadata:
                    tokens = getattr(response.usage_metadata, "total_token_count", 0)
                return {"content": response.text or "", "tokens": tokens}

            if provider == LLMProvider.OPENAI:
                response = await client.chat.completions.create(
                    model=self.llm_config.model,
                    messages=[
                        {"role": "system", "content": sys_prompt},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=temp,
                    max_tokens=self.llm_config.max_tokens,
                )
                return {
                    "content": response.choices[0].message.content or "",
                    "tokens": response.usage.total_tokens if response.usage else 0,
                }

            if provider == LLMProvider.ANTHROPIC:
                response = await client.messages.create(
                    model=self.llm_config.model,
                    system=sys_prompt,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=temp,
                    max_tokens=self.llm_config.max_tokens,
                )
                return {
                    "content": response.content[0].text if response.content else "",
                    "tokens": (response.usage.input_tokens + response.usage.output_tokens)
                    if response.usage
                    else 0,
                }

            raise ValueError(f"Unsupported provider: {provider}")

        except Exception as exc:
            logging.getLogger(__name__).error("LLM call failed: %s", exc)
            raise

    async def invoke(
        self,
        prompt: str,
        context: dict[str, Any] | None = None,
    ) -> AgentResponse:
        """
        Invoke the agent with a prompt.

        Args:
            prompt: The task or question for the agent.
            context: Optional additional context.

        Returns:
            Structured response from the agent.
        """
        start_time = time.time()

        self.conversation_history.append(AgentMessage(role="user", content=prompt))

        try:
            result = await self._reason(prompt, context)
            latency = (time.time() - start_time) * 1000

            response = AgentResponse(
                agent_role=self.role,
                content=result.get("content", ""),
                structured_output=result.get("structured", None),
                tokens_used=result.get("tokens", 0),
                latency_ms=latency,
                success=True,
            )

            self.conversation_history.append(
                AgentMessage(
                    role="assistant",
                    content=response.content,
                    metadata={"tokens": response.tokens_used},
                )
            )

            return response

        except Exception as exc:
            latency = (time.time() - start_time) * 1000
            return AgentResponse(
                agent_role=self.role,
                content="",
                latency_ms=latency,
                success=False,
                error=str(exc),
            )

    @abstractmethod
    async def _reason(
        self,
        prompt: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Core reasoning method — implemented by each specialized agent.

        Returns:
            Dict with 'content' (str), 'structured' (optional dict), 'tokens' (int).
        """
        ...

    def reset(self) -> None:
        """Clear conversation history."""
        self.conversation_history.clear()

    def __repr__(self) -> str:
        return (
            f"<{self.name} model={self.llm_config.model} "
            f"tools={[t.value for t in self.permitted_tools]}>"
        )
