"""Baseline workload generator for false positive measurement."""

import time
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from benchmark.collector import AlertCollector, CollectionWindow
from benchmark.runner import AttackRunner

console = Console()


class BaselineRunner:
    """Runs benign baseline workloads for FP measurement."""

    def __init__(
        self,
        manifest_path: Path = Path("attacks/attack_manifest.yaml"),
        container_name: str = "soc-target",
    ):
        self.manifest_path = manifest_path
        self.container_name = container_name
        self.runner = AttackRunner(manifest_path, container_name)
        self.manifest = self._load_manifest()

    def _load_manifest(self) -> dict[str, Any]:
        """Load the attack manifest YAML."""
        with open(self.manifest_path) as f:
            return yaml.safe_load(f)

    def run_baseline(
        self,
        duration_minutes: int = 5,
        iterations: int = 10,
    ) -> CollectionWindow:
        """Run baseline benign workloads.

        Returns the collection window for FP analysis.
        """
        baseline_tasks = self.manifest.get("baseline", [])

        if not baseline_tasks:
            console.print("[yellow]No baseline tasks defined in manifest[/yellow]")
            return CollectionWindow(start=datetime.now(), end=datetime.now())

        start_time = datetime.now()
        console.print(f"\n[bold blue]Running baseline workload ({iterations} iterations)[/bold blue]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Running baseline...", total=iterations)

            for i in range(iterations):
                progress.update(task, description=f"Iteration {i + 1}/{iterations}")

                for baseline in baseline_tasks:
                    name = baseline["name"]
                    command = baseline["command"].strip()

                    success, stdout, stderr = self.runner.execute_command(command)

                    status = "[green]OK[/]" if success else "[yellow]WARN[/]"
                    console.print(f"  {name}: {status}")

                    # Wait between tasks
                    delay = baseline.get("duration_seconds", 2)
                    time.sleep(delay)

                progress.advance(task)

                # Pause between iterations
                if i < iterations - 1:
                    time.sleep(5)

        end_time = datetime.now()

        console.print(f"\n[green]Baseline completed in {(end_time - start_time).seconds}s[/green]")

        return CollectionWindow(start=start_time, end=end_time)


def run_baseline(
    manifest_path: str = "attacks/attack_manifest.yaml",
    iterations: int = 10,
    es_host: str = "localhost",
    es_port: int = 9200,
) -> dict[str, Any]:
    """Run baseline and calculate false positive rate.

    Returns:
        Dictionary with baseline statistics including FP rate.
    """
    runner = BaselineRunner(manifest_path=Path(manifest_path))

    console.print("\n[bold blue]SOC Detection Benchmark - Baseline Runner[/bold blue]\n")

    # Run baseline workloads
    window = runner.run_baseline(iterations=iterations)

    # Collect logs and calculate FP rate
    collector = AlertCollector(es_host=es_host, es_port=es_port)

    # Wait for logs to be indexed (Filebeat needs time to ship logs)
    console.print("\n[dim]Waiting for log indexing (30s)...[/dim]")
    time.sleep(30)

    total_logs = collector.count_logs_in_window(window)
    duration_hours = (window.end - window.start).total_seconds() / 3600

    # Calculate alerts per hour for detection-related keywords
    detection_keywords = [
        "exec", "EXECVE", "cron_mod", "user_add", "user_mod",
        "priv_esc", "file_delete", "shell_history", "network_connect",
    ]
    alert_rate = collector.get_alert_rate(window, detection_keywords)

    results = {
        "window_start": window.start.isoformat(),
        "window_end": window.end.isoformat(),
        "duration_seconds": (window.end - window.start).total_seconds(),
        "duration_hours": duration_hours,
        "iterations": iterations,
        "total_logs": total_logs,
        "logs_per_hour": total_logs / duration_hours if duration_hours > 0 else 0,
        "detection_alert_rate_per_hour": alert_rate,
    }

    console.print("\n[bold]Baseline Statistics:[/bold]")
    console.print(f"  Duration: {results['duration_seconds']:.1f}s")
    console.print(f"  Total logs: {results['total_logs']}")
    console.print(f"  Log rate: {results['logs_per_hour']:.1f}/hour")
    console.print(f"  Detection alert rate: {results['detection_alert_rate_per_hour']:.1f}/hour")

    return results


if __name__ == "__main__":
    results = run_baseline()
