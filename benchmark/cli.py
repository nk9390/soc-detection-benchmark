"""CLI interface for the SOC Detection Benchmark."""

import json
import sys
import time
from datetime import datetime
from pathlib import Path

import click
from rich.console import Console

console = Console()


@click.group()
@click.version_option(version="1.0.0")
def main():
    """SOC Detection Engineering Benchmark CLI."""
    pass


@main.command()
@click.option(
    "--manifest",
    "-m",
    default="attacks/attack_manifest.yaml",
    help="Path to attack manifest YAML",
)
@click.option(
    "--delay",
    "-d",
    default=2.0,
    help="Delay between attacks in seconds",
)
@click.option(
    "--output",
    "-o",
    default="results",
    help="Output directory for results",
)
def run_attacks(manifest: str, delay: float, output: str):
    """Execute all attacks from the manifest."""
    from benchmark.runner import run_attacks as _run_attacks

    try:
        run = _run_attacks(manifest_path=manifest, delay=delay)

        # Save raw results
        output_path = Path(output)
        output_path.mkdir(parents=True, exist_ok=True)

        results_file = output_path / f"attacks_{run.run_id}.json"
        results_data = {
            "run_id": run.run_id,
            "start_time": run.start_time.isoformat(),
            "end_time": run.end_time.isoformat() if run.end_time else None,
            "attacks": [
                {
                    "technique_id": r.technique_id,
                    "technique_name": r.technique_name,
                    "tactic": r.tactic,
                    "test_name": r.test_name,
                    "command": r.command,
                    "start_time": r.start_time.isoformat(),
                    "end_time": r.end_time.isoformat(),
                    "success": r.success,
                    "output": r.output,
                    "error": r.error,
                }
                for r in run.attack_results
            ],
        }
        results_file.write_text(json.dumps(results_data, indent=2))

        console.print(f"\n[green]Results saved to {results_file}[/green]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@main.command()
@click.option(
    "--manifest",
    "-m",
    default="attacks/attack_manifest.yaml",
    help="Path to attack manifest YAML",
)
@click.option(
    "--iterations",
    "-i",
    default=10,
    help="Number of baseline iterations",
)
@click.option(
    "--output",
    "-o",
    default="results",
    help="Output directory for results",
)
def run_baseline(manifest: str, iterations: int, output: str):
    """Run baseline workloads for FP measurement."""
    from benchmark.baseline import run_baseline as _run_baseline

    try:
        results = _run_baseline(manifest_path=manifest, iterations=iterations)

        # Save baseline results
        output_path = Path(output)
        output_path.mkdir(parents=True, exist_ok=True)

        baseline_file = output_path / "baseline_latest.json"
        baseline_file.write_text(json.dumps(results, indent=2))

        console.print(f"\n[green]Baseline results saved to {baseline_file}[/green]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@main.command()
@click.option(
    "--attacks-file",
    "-a",
    required=True,
    help="Path to attacks results JSON",
)
@click.option(
    "--baseline-file",
    "-b",
    default=None,
    help="Path to baseline results JSON (optional)",
)
@click.option(
    "--output",
    "-o",
    default="results",
    help="Output directory for report",
)
def report(attacks_file: str, baseline_file: str | None, output: str):
    """Generate benchmark report from attack results."""
    import json
    from datetime import datetime

    from benchmark.collector import CollectionWindow
    from benchmark.metrics import calculate_metrics
    from benchmark.report import generate_report
    from benchmark.runner import AttackResult, BenchmarkRun

    try:
        # Load attack results
        with open(attacks_file) as f:
            attacks_data = json.load(f)

        # Reconstruct BenchmarkRun
        run = BenchmarkRun(
            run_id=attacks_data["run_id"],
            start_time=datetime.fromisoformat(attacks_data["start_time"]),
            end_time=datetime.fromisoformat(attacks_data["end_time"])
            if attacks_data["end_time"]
            else None,
            attack_results=[
                AttackResult(
                    technique_id=a["technique_id"],
                    technique_name=a["technique_name"],
                    tactic=a["tactic"],
                    test_name=a["test_name"],
                    command=a.get("command", ""),
                    start_time=datetime.fromisoformat(a["start_time"]),
                    end_time=datetime.fromisoformat(a["end_time"]),
                    success=a["success"],
                    output=a.get("output", ""),
                    error=a.get("error", ""),
                )
                for a in attacks_data["attacks"]
            ],
        )

        # Load baseline if provided
        baseline_window = None
        if baseline_file:
            with open(baseline_file) as f:
                baseline_data = json.load(f)
            baseline_window = CollectionWindow(
                start=datetime.fromisoformat(baseline_data["window_start"]),
                end=datetime.fromisoformat(baseline_data["window_end"]),
            )

        # Calculate metrics
        metrics = calculate_metrics(run, baseline_window=baseline_window)

        # Generate report
        generate_report(metrics, output_dir=output)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@main.command()
@click.option(
    "--manifest",
    "-m",
    default="attacks/attack_manifest.yaml",
    help="Path to attack manifest YAML",
)
@click.option(
    "--baseline-iterations",
    "-b",
    default=5,
    help="Number of baseline iterations",
)
@click.option(
    "--attack-delay",
    "-d",
    default=2.0,
    help="Delay between attacks in seconds",
)
@click.option(
    "--output",
    "-o",
    default="results",
    help="Output directory",
)
def benchmark(manifest: str, baseline_iterations: int, attack_delay: float, output: str):
    """Run full benchmark: baseline + attacks + report."""
    import time

    from benchmark.baseline import run_baseline as _run_baseline
    from benchmark.collector import CollectionWindow
    from benchmark.metrics import calculate_metrics
    from benchmark.report import generate_report
    from benchmark.runner import run_attacks as _run_attacks

    console.print("\n[bold blue]═══ SOC Detection Engineering Benchmark ═══[/bold blue]\n")

    try:
        # Phase 1: Baseline
        console.print("[bold]Phase 1: Running baseline workload[/bold]\n")
        baseline_results = _run_baseline(
            manifest_path=manifest,
            iterations=baseline_iterations,
        )

        baseline_window = CollectionWindow(
            start=datetime.fromisoformat(baseline_results["window_start"]),
            end=datetime.fromisoformat(baseline_results["window_end"]),
        )

        # Brief pause between phases
        console.print("\n[dim]Pausing before attack phase...[/dim]")
        time.sleep(5)

        # Phase 2: Attacks
        console.print("\n[bold]Phase 2: Executing attacks[/bold]\n")
        run = _run_attacks(manifest_path=manifest, delay=attack_delay)

        # Save attack details for diagnostic purposes
        output_path = Path(output)
        output_path.mkdir(parents=True, exist_ok=True)
        attacks_file = output_path / f"attacks_{run.run_id}.json"
        attacks_data = {
            "run_id": run.run_id,
            "start_time": run.start_time.isoformat(),
            "end_time": run.end_time.isoformat() if run.end_time else None,
            "attacks": [
                {
                    "technique_id": r.technique_id,
                    "technique_name": r.technique_name,
                    "tactic": r.tactic,
                    "test_name": r.test_name,
                    "command": r.command,
                    "start_time": r.start_time.isoformat(),
                    "end_time": r.end_time.isoformat(),
                    "success": r.success,
                    "output": r.output,
                    "error": r.error,
                }
                for r in run.attack_results
            ],
        }
        attacks_file.write_text(json.dumps(attacks_data, indent=2))
        console.print(f"[dim]Attack details saved to {attacks_file}[/dim]")

        # Wait for logs to be indexed (Filebeat needs time to ship logs)
        console.print("\n[dim]Waiting for log indexing (30s)...[/dim]")
        time.sleep(30)

        # Phase 3: Analysis
        console.print("\n[bold]Phase 3: Calculating metrics[/bold]\n")
        metrics = calculate_metrics(run, baseline_window=baseline_window)

        # Phase 4: Report
        console.print("\n[bold]Phase 4: Generating report[/bold]\n")
        paths = generate_report(metrics, output_dir=output)

        console.print("\n[bold green]═══ Benchmark Complete ═══[/bold green]")
        console.print(f"\nView report: {paths['markdown']}")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@main.command()
def status():
    """Check status of the lab environment."""
    import docker

    try:
        client = docker.from_env()

        containers = {
            "soc-elasticsearch": "Elasticsearch",
            "soc-kibana": "Kibana",
            "soc-filebeat": "Filebeat",
            "soc-target": "Target",
        }

        console.print("\n[bold]Lab Environment Status[/bold]\n")

        all_running = True
        for container_name, display_name in containers.items():
            try:
                container = client.containers.get(container_name)
                status = container.status
                if status == "running":
                    console.print(f"  {display_name}: [green]running[/green]")
                else:
                    console.print(f"  {display_name}: [yellow]{status}[/yellow]")
                    all_running = False
            except docker.errors.NotFound:
                console.print(f"  {display_name}: [red]not found[/red]")
                all_running = False

        if all_running:
            console.print("\n[green]Lab is ready![/green]")
        else:
            console.print("\n[yellow]Run 'make up' to start the lab[/yellow]")

    except docker.errors.DockerException as e:
        console.print(f"[red]Docker error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
