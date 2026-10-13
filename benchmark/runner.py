"""Attack execution runner for the SOC Detection Benchmark."""

import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import docker
import yaml
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


@dataclass
class AttackResult:
    """Result of a single attack execution."""

    technique_id: str
    technique_name: str
    tactic: str
    test_name: str
    command: str
    start_time: datetime
    end_time: datetime
    success: bool
    output: str = ""
    error: str = ""


@dataclass
class BenchmarkRun:
    """A complete benchmark run with all attack results."""

    run_id: str
    start_time: datetime
    end_time: datetime | None = None
    attack_results: list[AttackResult] = field(default_factory=list)
    baseline_results: list[dict[str, Any]] = field(default_factory=list)


class AttackRunner:
    """Executes attacks on the target container."""

    def __init__(
        self,
        manifest_path: Path = Path("attacks/attack_manifest.yaml"),
        container_name: str = "soc-target",
    ):
        self.manifest_path = manifest_path
        self.container_name = container_name
        self.docker_client = docker.from_env()
        self.manifest = self._load_manifest()

    def _load_manifest(self) -> dict[str, Any]:
        """Load the attack manifest YAML."""
        with open(self.manifest_path) as f:
            return yaml.safe_load(f)

    def _get_container(self):
        """Get the target container."""
        try:
            return self.docker_client.containers.get(self.container_name)
        except docker.errors.NotFound:
            raise RuntimeError(
                f"Container '{self.container_name}' not found. "
                "Run 'make up' to start the lab environment."
            )

    def execute_command(self, command: str, timeout: int = 30) -> tuple[bool, str, str]:
        """Execute a command in the target container."""
        container = self._get_container()

        try:
            exit_code, output = container.exec_run(
                cmd=["bash", "-c", command],
                user="root",
                demux=True,
            )

            stdout = output[0].decode() if output[0] else ""
            stderr = output[1].decode() if output[1] else ""

            return exit_code == 0, stdout, stderr

        except Exception as e:
            return False, "", str(e)

    def run_attack(self, technique: dict[str, Any], test: dict[str, Any]) -> AttackResult:
        """Run a single attack test."""
        start_time = datetime.now()

        command = test["command"].strip()
        success, stdout, stderr = self.execute_command(command)

        end_time = datetime.now()

        # Run cleanup if provided
        if test.get("cleanup"):
            self.execute_command(test["cleanup"])

        return AttackResult(
            technique_id=technique["id"],
            technique_name=technique["name"],
            tactic=technique["tactic"],
            test_name=test["name"],
            command=command,
            start_time=start_time,
            end_time=end_time,
            success=success,
            output=stdout,
            error=stderr,
        )

    def run_all_attacks(self, delay_between: float = 2.0) -> BenchmarkRun:
        """Run all attacks defined in the manifest."""
        run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        benchmark_run = BenchmarkRun(
            run_id=run_id,
            start_time=datetime.now(),
        )

        techniques = self.manifest.get("techniques", [])

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Running attacks...", total=None)

            for technique in techniques:
                for test in technique.get("atomic_tests", []):
                    progress.update(
                        task,
                        description=f"[cyan]{technique['id']}[/] - {test['name']}",
                    )

                    result = self.run_attack(technique, test)
                    benchmark_run.attack_results.append(result)

                    status = "[green]OK[/]" if result.success else "[red]FAIL[/]"
                    console.print(f"  {technique['id']} - {test['name']}: {status}")

                    # Delay between attacks for log correlation
                    time.sleep(delay_between)

        benchmark_run.end_time = datetime.now()
        return benchmark_run

    def run_single_technique(self, technique_id: str) -> list[AttackResult]:
        """Run all tests for a single technique."""
        results = []

        for technique in self.manifest.get("techniques", []):
            if technique["id"] == technique_id:
                for test in technique.get("atomic_tests", []):
                    result = self.run_attack(technique, test)
                    results.append(result)

        return results


def run_attacks(
    manifest_path: str = "attacks/attack_manifest.yaml",
    delay: float = 2.0,
) -> BenchmarkRun:
    """Main entry point for running attacks."""
    runner = AttackRunner(manifest_path=Path(manifest_path))

    console.print("\n[bold blue]SOC Detection Benchmark - Attack Runner[/bold blue]\n")
    console.print(f"Manifest: {manifest_path}")
    console.print(f"Target container: {runner.container_name}")
    console.print()

    return runner.run_all_attacks(delay_between=delay)


if __name__ == "__main__":
    run = run_attacks()
    console.print(f"\n[bold green]Completed {len(run.attack_results)} attacks[/bold green]")
