"""
Integration test — runs Co-AI-RedTeam against the vulnerable test target.

Usage:
    python test_targets/run_scan.py

Prerequisites:
    - Set GEMINI_API_KEY (or OPENAI_API_KEY / ANTHROPIC_API_KEY) in .env
    - pip install -e ".[dev]"
"""

import asyncio
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))


async def run_integration_test() -> None:
    """Run a full scan against the deliberately vulnerable app."""
    from rich.console import Console
    from rich.panel import Panel

    console = Console()

    console.print(
        Panel.fit(
            "[bold cyan]Co-AI-RedTeam Integration Test[/bold cyan]\n"
            "[dim]Scanning test_targets/vulnerable_app/[/dim]",
            border_style="cyan",
        )
    )

    # ── Step 1: Verify API key ─────────────────────────────────────────
    console.print("\n[bold]Step 1:[/bold] Checking API key...")

    from co_redteam.config import LLMConfig

    llm_config = LLMConfig()
    try:
        api_key = llm_config.resolve_api_key()
        if not api_key or api_key.startswith("your-"):
            console.print(
                "[red]❌ No valid API key found![/red]\n"
                "Set one in .env file:\n"
                "  GEMINI_API_KEY=your-actual-key\n"
                "  OPENAI_API_KEY=your-actual-key\n"
                "  ANTHROPIC_API_KEY=your-actual-key"
            )
            return
        provider = llm_config.provider.value
        console.print(f"  ✅ Using [green]{provider}[/green] provider")
    except Exception as exc:
        console.print(f"[red]❌ API key error: {exc}[/red]")
        return

    # ── Step 2: Test LLM connection ────────────────────────────────────
    console.print("\n[bold]Step 2:[/bold] Testing LLM connection...")

    from co_redteam.agents.analysis import AnalysisAgent

    test_agent = AnalysisAgent(llm_config)
    try:
        result = await test_agent.invoke("Say 'OK' if you can hear me. One word only.")
        if result.success:
            console.print(f"  ✅ LLM responded: [green]{result.content[:50]}[/green]")
        else:
            console.print(f"  [red]❌ LLM call failed: {result.content[:100]}[/red]")
            return
    except Exception as exc:
        console.print(f"  [red]❌ LLM connection error: {exc}[/red]")
        return

    # ── Step 3: Run full scan ──────────────────────────────────────────
    console.print("\n[bold]Step 3:[/bold] Running full pipeline scan...")

    from co_redteam import Orchestrator, RedTeamConfig

    target_path = PROJECT_ROOT / "test_targets" / "vulnerable_app"

    config = RedTeamConfig(
        target_path=target_path,
        exploit={"enabled": False},  # Skip exploitation for quick test
        patch={"enabled": False},    # Skip patching for quick test
        report={
            "output_dir": str(PROJECT_ROOT / "test_output"),
            "generate_sarif": True,
            "generate_markdown": True,
        },
        memory={"enabled": True, "storage_dir": str(PROJECT_ROOT / "test_output" / ".memory")},
    )

    try:
        orchestrator = Orchestrator(config)
        result = await orchestrator.run()
    except Exception as exc:
        console.print(f"\n[red]❌ Scan failed with error:[/red]\n{exc}")
        import traceback
        traceback.print_exc()
        return

    # ── Step 4: Verify results ─────────────────────────────────────────
    console.print("\n[bold]Step 4:[/bold] Verifying results...")

    vuln_count = result.get("vulnerabilities_found", 0)
    duration = result.get("duration_seconds", 0)
    report_paths = result.get("report_paths", {})

    if vuln_count > 0:
        console.print(f"  ✅ Found [green]{vuln_count}[/green] vulnerabilities")
    else:
        console.print("  [yellow]⚠️ No vulnerabilities found (LLM may need tuning)[/yellow]")

    if "sarif" in report_paths:
        console.print(f"  ✅ SARIF report: [green]{report_paths['sarif']}[/green]")
    if "markdown" in report_paths:
        console.print(f"  ✅ Markdown report: [green]{report_paths['markdown']}[/green]")

    console.print(f"  ⏱️ Duration: {duration:.1f}s")

    # ── Summary ────────────────────────────────────────────────────────
    console.print(
        Panel.fit(
            f"[bold green]Integration Test Complete[/bold green]\n"
            f"Vulnerabilities: {vuln_count} | Duration: {duration:.1f}s\n"
            f"Reports: {', '.join(report_paths.keys()) or 'none'}",
            border_style="green",
        )
    )


if __name__ == "__main__":
    asyncio.run(run_integration_test())
