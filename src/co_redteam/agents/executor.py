"""
Executor Agent — Runs commands in isolated sandbox environments.

Executes exploitation and validation commands within Docker containers
to ensure safety and reproducibility.
"""

from __future__ import annotations

import asyncio
import contextlib
import tempfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from co_redteam.agents.base import AgentRole, BaseAgent
from co_redteam.config import LLMConfig, SandboxConfig


class ExecutionResult(BaseModel):
    """Result from a sandboxed command execution."""

    command: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    timed_out: bool = False
    duration_ms: float = 0.0
    success: bool = False
    sandbox_id: str = ""


class ExecutorAgent(BaseAgent):
    """
    Sandboxed execution agent.

    Runs exploit commands and validation scripts inside
    isolated Docker containers for safety and reproducibility.
    """

    def __init__(
        self,
        llm_config: LLMConfig,
        sandbox_config: SandboxConfig | None = None,
    ) -> None:
        super().__init__(
            role=AgentRole.EXECUTOR,
            llm_config=llm_config,
            system_prompt="",
        )
        self.sandbox_config = sandbox_config or SandboxConfig()

    async def execute_command(
        self,
        command: str,
        working_dir: str | None = None,
        env_vars: dict[str, str] | None = None,
    ) -> ExecutionResult:
        """
        Execute a command in the sandbox.

        Args:
            command: Bash command or script to execute.
            working_dir: Working directory inside the container.
            env_vars: Environment variables to set.

        Returns:
            ExecutionResult with stdout, stderr, exit code.
        """
        if self.sandbox_config.enabled:
            return await self._execute_docker(command, working_dir, env_vars)
        return await self._execute_local(command, working_dir, env_vars)

    async def execute_python(
        self,
        script: str,
        working_dir: str | None = None,
    ) -> ExecutionResult:
        """
        Execute a Python script in the sandbox.

        Args:
            script: Python source code to execute.
            working_dir: Working directory.

        Returns:
            ExecutionResult with output.
        """
        # Write script to temp file and execute
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as tmp:
            tmp.write(script)
            tmp_path = tmp.name

        command = f"python3 {tmp_path}"
        result = await self.execute_command(command, working_dir)
        result.command = f"python3 <<SCRIPT\n{script[:200]}...\nSCRIPT"

        # Cleanup
        with contextlib.suppress(OSError):
            Path(tmp_path).unlink()

        return result

    async def _execute_docker(
        self,
        command: str,
        working_dir: str | None = None,
        env_vars: dict[str, str] | None = None,
    ) -> ExecutionResult:
        """Execute command inside a Docker container.

        All Docker SDK calls are synchronous, so we offload them to a
        thread pool via ``asyncio.to_thread`` to avoid blocking the
        event loop.
        """
        import asyncio
        import time

        try:
            import docker

            # Docker SDK is synchronous — run in thread pool
            client = await asyncio.to_thread(docker.from_env)
            start_time = time.time()

            container = await asyncio.to_thread(
                client.containers.run,
                image=self.sandbox_config.image,
                command=["bash", "-c", command],
                working_dir=working_dir or "/workspace",
                environment=env_vars or {},
                mem_limit=self.sandbox_config.memory_limit,
                network_disabled=self.sandbox_config.network_disabled,
                remove=False,
                detach=True,
            )

            try:
                exit_result = await asyncio.to_thread(
                    container.wait, timeout=self.sandbox_config.timeout_seconds,
                )
                exit_code = exit_result.get("StatusCode", -1)
                stdout_bytes = await asyncio.to_thread(
                    container.logs, stdout=True, stderr=False,
                )
                stderr_bytes = await asyncio.to_thread(
                    container.logs, stdout=False, stderr=True,
                )
                stdout = stdout_bytes.decode("utf-8", errors="replace")
                stderr = stderr_bytes.decode("utf-8", errors="replace")
                timed_out = False
            except Exception:
                await asyncio.to_thread(container.stop, timeout=5)
                stdout = ""
                stderr = "Execution timed out"
                exit_code = -1
                timed_out = True

            duration = (time.time() - start_time) * 1000

            if self.sandbox_config.remove_after:
                await asyncio.to_thread(container.remove, force=True)

            return ExecutionResult(
                command=command,
                stdout=stdout[:10000],  # Cap output size
                stderr=stderr[:5000],
                exit_code=exit_code,
                timed_out=timed_out,
                duration_ms=duration,
                success=exit_code == 0,
                sandbox_id=container.short_id if not self.sandbox_config.remove_after else "",
            )

        except ImportError:
            # Docker SDK not available — fall back to local with warning
            import logging

            logging.getLogger(__name__).warning(
                "⚠️ Docker SDK not available — falling back to UNSANDBOXED local execution! "
                "Install docker: pip install docker, or use --no-sandbox flag explicitly."
            )
            return await self._execute_local(command, working_dir, env_vars)
        except Exception as exc:
            return ExecutionResult(
                command=command,
                stderr=f"Docker execution failed: {exc}",
                success=False,
            )

    async def _execute_local(
        self,
        command: str,
        working_dir: str | None = None,
        env_vars: dict[str, str] | None = None,
    ) -> ExecutionResult:
        """Execute command locally (fallback when Docker unavailable)."""
        import os
        import time

        start_time = time.time()

        env = os.environ.copy()
        if env_vars:
            env.update(env_vars)

        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=working_dir,
                env=env,
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.sandbox_config.timeout_seconds,
                )
                timed_out = False
            except asyncio.TimeoutError:
                process.kill()
                stdout_bytes = b""
                stderr_bytes = b"Execution timed out"
                timed_out = True

            duration = (time.time() - start_time) * 1000

            return ExecutionResult(
                command=command,
                stdout=stdout_bytes.decode("utf-8", errors="replace")[:10000],
                stderr=stderr_bytes.decode("utf-8", errors="replace")[:5000],
                exit_code=process.returncode or -1,
                timed_out=timed_out,
                duration_ms=duration,
                success=process.returncode == 0,
            )

        except Exception as exc:
            return ExecutionResult(
                command=command,
                stderr=f"Local execution failed: {exc}",
                success=False,
            )

    async def _reason(
        self,
        prompt: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Executor doesn't use LLM reasoning — it runs commands."""
        return {"content": "Executor agent operates via execute_command()", "tokens": 0}
