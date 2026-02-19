"""
Co-AI-RedTeam CLI — Command-line interface.

Usage:
    co-redteam scan ./target-project
    co-redteam scan ./target-project --severity high
    co-redteam scan ./target-project --hint "Check auth module"
    co-redteam memory stats
    co-redteam memory list
    cart scan ./target-project  # alias
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from co_redteam import __version__
from co_redteam.config import RedTeamConfig, SeverityLevel

console = Console()

BANNER = r"""
   ____              _    ___   ____          _ _____
  / ___|___         / \  |_ _| |  _ \ ___  __| |_   _|__  __ _ _ __ ___
 | |   / _ \ _____ / _ \  | |  | |_) / _ \/ _` | | |/ _ \/ _` | '_ ` _ \
 | |__| (_) |_____/ ___ \ | |  |  _ <  __/ (_| | | |  __/ (_| | | | | | |
  \____\___/     /_/   \_\___| |_| \_\___|\__,_| |_|\___|\__,_|_| |_| |_|
"""


@click.group()
@click.version_option(version=__version__, prog_name="co-ai-redteam")
def main() -> None:
    """Co-AI-RedTeam: AI-powered multi-agent red teaming framework."""


@main.command()
@click.argument("target", type=click.Path(exists=True))
@click.option(
    "--severity",
    type=click.Choice(["critical", "high", "medium", "low"], case_sensitive=False),
    default="low",
    help="Minimum severity level to report.",
)
@click.option("--hint", type=str, default=None, help="Vulnerability hint to guide analysis.")
@click.option("--model", type=str, default="gemini-2.5-pro", help="LLM model to use.")
@click.option("--api-key", type=str, default=None, help="LLM API key (or set env var).")
@click.option(
    "--output", type=click.Path(), default="reports", help="Output directory for reports."
)
@click.option("--no-exploit", is_flag=True, help="Skip exploitation phase.")
@click.option("--no-patch", is_flag=True, help="Skip patching phase.")
@click.option("--no-sarif", is_flag=True, help="Skip SARIF report generation.")
@click.option("--no-sandbox", is_flag=True, help="Disable Docker sandbox (use local execution).")
@click.option("--config", type=click.Path(exists=True), default=None, help="YAML config file.")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output.")
def scan(
    target: str,
    severity: str,
    hint: str | None,
    model: str,
    api_key: str | None,
    output: str,
    no_exploit: bool,
    no_patch: bool,
    no_sarif: bool,
    no_sandbox: bool,
    config: str | None,
    verbose: bool,
) -> None:
    """Run a security assessment on TARGET directory or file."""
    console.print(BANNER, style="bold red")
    console.print(f"[dim]v{__version__} — Multi-Agent Red Team Assessment[/dim]\n")

    # Build config
    cfg = RedTeamConfig.from_file(Path(config)) if config else RedTeamConfig()

    cfg.target_path = Path(target).resolve()
    cfg.discovery.min_severity = SeverityLevel(severity)
    cfg.vulnerability_hint = hint
    cfg.llm.model = model
    cfg.report.output_dir = Path(output)
    cfg.report.generate_sarif = not no_sarif
    cfg.sandbox.enabled = not no_sandbox
    cfg.verbose = verbose

    if api_key:
        from pydantic import SecretStr

        cfg.llm.api_key = SecretStr(api_key)

    if no_exploit:
        cfg.exploit.enabled = False
    if no_patch:
        cfg.patch.enabled = False

    # Validate target
    target_path = cfg.target_path
    if not target_path.exists():
        console.print(f"[red]Error:[/red] Target not found: {target_path}")
        sys.exit(1)

    # Run pipeline
    from co_redteam.orchestrator import Orchestrator

    orchestrator = Orchestrator(cfg)
    result = asyncio.run(orchestrator.run())

    # Exit code based on findings
    if result["vulnerabilities_found"] > 0:
        sys.exit(1)  # Non-zero = findings exist (useful for CI)
    sys.exit(0)


@main.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--output", type=click.Path(), default=None, help="Output YAML file path.")
def init(target: str, output: str | None) -> None:
    """Generate a default configuration file for TARGET project."""
    cfg = RedTeamConfig(target_path=Path(target).resolve())

    output_path = Path(output) if output else Path(target) / ".co-redteam.yml"
    cfg.to_file(output_path)

    console.print(f"[green]✓[/green] Config written to [bold]{output_path}[/bold]")
    console.print("[dim]Edit this file to customize your assessment.[/dim]")


@main.group()
def memory() -> None:
    """Manage the security experience memory store."""


@memory.command()
@click.option(
    "--dir", "memory_dir", type=click.Path(), default=".cart_memory", help="Memory directory."
)
def stats(memory_dir: str) -> None:
    """Show memory store statistics."""
    from co_redteam.memory.store import MemoryStore

    store = MemoryStore(Path(memory_dir))
    s = store.get_stats()

    table = Table(title="🧠 Security Memory Store", border_style="cyan")
    table.add_column("Layer", style="bold")
    table.add_column("Count", justify="right")
    table.add_row("Vulnerability Patterns", str(s["patterns"]))
    table.add_row("Strategies", str(s["strategies"]))
    table.add_row("Technical Actions", str(s["actions"]))
    table.add_row("Total", str(sum(s.values())), style="bold")

    console.print(table)


@memory.command(name="list")
@click.option(
    "--dir", "memory_dir", type=click.Path(), default=".cart_memory", help="Memory directory."
)
@click.option(
    "--layer", type=click.Choice(["patterns", "strategies", "actions", "all"]), default="all"
)
def memory_list(memory_dir: str, layer: str) -> None:
    """List items in the memory store."""
    from co_redteam.memory.store import MemoryStore

    store = MemoryStore(Path(memory_dir))

    if layer in ("patterns", "all"):
        patterns = store.get_all_patterns()
        if patterns:
            table = Table(title="Vulnerability Patterns", border_style="red")
            table.add_column("ID")
            table.add_column("CWE")
            table.add_column("Name")
            table.add_column("Confidence", justify="right")
            for p in patterns:
                table.add_row(p.id, p.cwe_class, p.pattern_name, f"{p.confidence:.0%}")
            console.print(table)

    if layer in ("strategies", "all"):
        strategies = store.get_all_strategies()
        if strategies:
            table = Table(title="Strategies", border_style="yellow")
            table.add_column("ID")
            table.add_column("Class")
            table.add_column("Name")
            for s in strategies:
                table.add_row(s.id, s.vulnerability_class, s.strategy_name)
            console.print(table)

    if layer in ("actions", "all"):
        actions = store.get_all_actions()
        if actions:
            table = Table(title="Technical Actions", border_style="blue")
            table.add_column("ID")
            table.add_column("Name")
            table.add_column("Related Pattern")
            for a in actions:
                table.add_row(a.id, a.action_name, a.related_pattern)
            console.print(table)


@memory.command()
@click.option("--dir", "memory_dir", type=click.Path(), default=".cart_memory")
@click.argument("cwe_id")
def query(memory_dir: str, cwe_id: str) -> None:
    """Query memory by CWE ID."""
    from co_redteam.memory.store import MemoryStore

    store = MemoryStore(Path(memory_dir))
    results = store.query_by_cwe(cwe_id, top_k=5)

    if not results:
        console.print(f"[dim]No memory items found for {cwe_id}[/dim]")
        return

    for item in results:
        item_name = getattr(
            item, "pattern_name", getattr(item, "strategy_name", getattr(item, "action_name", "Unknown"))
        )
        console.print(
            Panel(
                f"[bold]{item.id}[/bold]: {item_name}",
                border_style="cyan",
            )
        )


if __name__ == "__main__":
    main()
