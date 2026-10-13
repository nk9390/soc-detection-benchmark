"""Tests for the SOC Detection Benchmark."""

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from benchmark.metrics import TechniqueMetrics, BenchmarkMetrics
from benchmark.runner import AttackResult, BenchmarkRun
from benchmark.report import ReportGenerator


class TestAttackResult:
    """Tests for AttackResult dataclass."""

    def test_create_attack_result(self):
        result = AttackResult(
            technique_id="T1059.004",
            technique_name="Unix Shell",
            tactic="execution",
            test_name="Execute shell commands",
            command="whoami",
            start_time=datetime.now(),
            end_time=datetime.now(),
            success=True,
            output="root",
        )

        assert result.technique_id == "T1059.004"
        assert result.success is True


class TestBenchmarkRun:
    """Tests for BenchmarkRun dataclass."""

    def test_create_benchmark_run(self):
        run = BenchmarkRun(
            run_id="test_001",
            start_time=datetime.now(),
        )

        assert run.run_id == "test_001"
        assert len(run.attack_results) == 0


class TestTechniqueMetrics:
    """Tests for TechniqueMetrics."""

    def test_detection_rate_calculation(self):
        metrics = TechniqueMetrics(
            technique_id="T1059.004",
            technique_name="Unix Shell",
            tactic="execution",
            tests_executed=10,
            tests_detected=8,
            detection_rate=0.8,
            mean_time_to_detect_seconds=1.5,
            alert_count=12,
            false_negative_count=2,
        )

        assert metrics.detection_rate == 0.8
        assert metrics.false_negative_count == 2


class TestBenchmarkMetrics:
    """Tests for BenchmarkMetrics."""

    def test_aggregate_metrics(self):
        metrics = BenchmarkMetrics(
            run_id="test_001",
            start_time=datetime.now(),
            end_time=datetime.now() + timedelta(minutes=5),
            total_attacks=20,
            total_detected=15,
            overall_detection_rate=0.75,
            mean_time_to_detect_seconds=2.0,
            false_positive_rate_per_hour=10.5,
            alert_volume_per_attack=3.2,
            technique_metrics=[],
            detection_gaps=["T1070.003 (Clear Command History)"],
        )

        assert metrics.overall_detection_rate == 0.75
        assert len(metrics.detection_gaps) == 1


class TestReportGenerator:
    """Tests for ReportGenerator."""

    def test_generate_markdown(self, tmp_path):
        generator = ReportGenerator(output_dir=tmp_path)

        metrics = BenchmarkMetrics(
            run_id="test_001",
            start_time=datetime.now(),
            end_time=datetime.now() + timedelta(minutes=5),
            total_attacks=10,
            total_detected=8,
            overall_detection_rate=0.8,
            mean_time_to_detect_seconds=1.5,
            false_positive_rate_per_hour=5.0,
            alert_volume_per_attack=2.0,
            technique_metrics=[
                TechniqueMetrics(
                    technique_id="T1059.004",
                    technique_name="Unix Shell",
                    tactic="execution",
                    tests_executed=5,
                    tests_detected=5,
                    detection_rate=1.0,
                    mean_time_to_detect_seconds=1.0,
                    alert_count=5,
                    false_negative_count=0,
                ),
            ],
            detection_gaps=[],
        )

        markdown = generator.generate_markdown(metrics)

        assert "# SOC Detection Benchmark Report" in markdown
        assert "test_001" in markdown
        assert "80.0%" in markdown

    def test_generate_json(self, tmp_path):
        generator = ReportGenerator(output_dir=tmp_path)

        metrics = BenchmarkMetrics(
            run_id="test_001",
            start_time=datetime.now(),
            end_time=datetime.now() + timedelta(minutes=5),
            total_attacks=10,
            total_detected=8,
            overall_detection_rate=0.8,
            mean_time_to_detect_seconds=1.5,
            false_positive_rate_per_hour=5.0,
            alert_volume_per_attack=2.0,
            technique_metrics=[],
            detection_gaps=[],
        )

        json_data = generator.generate_json(metrics)

        assert json_data["run_id"] == "test_001"
        assert json_data["summary"]["overall_detection_rate"] == 0.8


class TestManifestLoading:
    """Tests for manifest loading."""

    def test_manifest_structure(self):
        import yaml

        manifest_path = Path("attacks/attack_manifest.yaml")
        if manifest_path.exists():
            with open(manifest_path) as f:
                manifest = yaml.safe_load(f)

            assert "metadata" in manifest
            assert "techniques" in manifest
            assert len(manifest["techniques"]) > 0

            # Check technique structure
            technique = manifest["techniques"][0]
            assert "id" in technique
            assert "name" in technique
            assert "tactic" in technique
            assert "atomic_tests" in technique
