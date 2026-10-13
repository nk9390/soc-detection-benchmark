"""Regression tests for report wording and false positive rate reporting."""

import json
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from benchmark.collector import AlertCollector, CollectionWindow
from benchmark.metrics import BenchmarkMetrics, MetricsCalculator, TechniqueMetrics
from benchmark.report import ReportGenerator
from benchmark.runner import AttackResult, BenchmarkRun

RESULTS_DIR = Path(__file__).parent.parent / "results"
RECORDED_RUN = "report_20261010_110741"


def make_metrics(fp_rate: float | None) -> BenchmarkMetrics:
    """Create BenchmarkMetrics with a given false positive rate."""
    start = datetime(2026, 10, 10, 12, 0, 0)
    return BenchmarkMetrics(
        run_id="test_001",
        start_time=start,
        end_time=start + timedelta(minutes=5),
        total_attacks=1,
        total_detected=1,
        overall_detection_rate=1.0,
        mean_time_to_detect_seconds=3.2,
        false_positive_rate_per_hour=fp_rate,
        alert_volume_per_attack=1.0,
        technique_metrics=[],
        detection_gaps=[],
    )


def metrics_from_recorded_json(data: dict) -> BenchmarkMetrics:
    """Rebuild BenchmarkMetrics from a recorded JSON report."""
    summary = data["summary"]
    return BenchmarkMetrics(
        run_id=data["run_id"],
        start_time=datetime.fromisoformat(data["start_time"]),
        end_time=datetime.fromisoformat(data["end_time"]),
        total_attacks=summary["total_attacks"],
        total_detected=summary["total_detected"],
        overall_detection_rate=summary["overall_detection_rate"],
        mean_time_to_detect_seconds=summary["mean_time_to_detect_seconds"],
        false_positive_rate_per_hour=summary["false_positive_rate_per_hour"],
        alert_volume_per_attack=summary["alert_volume_per_attack"],
        technique_metrics=[TechniqueMetrics(**t) for t in data["technique_metrics"]],
        detection_gaps=data["detection_gaps"],
    )


class TestMethodologyWording:
    """The report must describe what the harness actually does."""

    def test_does_not_claim_sigma_rule_execution(self, tmp_path):
        md = ReportGenerator(output_dir=tmp_path).generate_markdown(make_metrics(None))

        assert "Elasticsearch with Sigma rules" not in md
        assert "Keyword-based Elasticsearch queries" in md
        assert "Sigma rules are not executed" in md

    def test_does_not_claim_atomic_red_team_execution(self, tmp_path):
        md = ReportGenerator(output_dir=tmp_path).generate_markdown(make_metrics(None))

        assert "**Attack Framework:** Atomic Red Team" not in md
        assert "Hand-written commands from the attack manifest" in md
        assert "Atomic Red Team tests are not executed" in md


class TestFalsePositiveRateReporting:
    """An unmeasured false positive rate must not be reported as zero."""

    def test_unmeasured_rate_is_not_zero_in_markdown(self, tmp_path):
        md = ReportGenerator(output_dir=tmp_path).generate_markdown(make_metrics(None))

        assert "| False Positive Rate | N/A (not measured) |" in md
        assert "0.0/hour" not in md

    def test_unmeasured_rate_is_null_in_json(self, tmp_path):
        report = ReportGenerator(output_dir=tmp_path).generate_json(make_metrics(None))

        assert report["summary"]["false_positive_rate_per_hour"] is None
        assert json.loads(json.dumps(report))["summary"]["false_positive_rate_per_hour"] is None

    def test_measured_zero_stays_zero(self, tmp_path):
        generator = ReportGenerator(output_dir=tmp_path)
        metrics = make_metrics(0.0)

        assert "| False Positive Rate | 0.0/hour |" in generator.generate_markdown(metrics)
        assert generator.generate_json(metrics)["summary"]["false_positive_rate_per_hour"] == 0.0

    def test_measured_rate_is_unchanged(self, tmp_path):
        generator = ReportGenerator(output_dir=tmp_path)
        metrics = make_metrics(5.0)

        assert "| False Positive Rate | 5.0/hour |" in generator.generate_markdown(metrics)
        assert generator.generate_json(metrics)["summary"]["false_positive_rate_per_hour"] == 5.0

    def test_console_summary_handles_unmeasured_rate(self, tmp_path):
        # Must not raise when the rate is unavailable
        ReportGenerator(output_dir=tmp_path).print_summary(make_metrics(None))


class TestFalsePositiveRateCalculation:
    """The calculator must distinguish 'no baseline' from a measured rate."""

    @staticmethod
    def make_run() -> BenchmarkRun:
        start = datetime(2026, 10, 10, 12, 0, 0)
        result = AttackResult(
            technique_id="T1136.001",
            technique_name="Local Account",
            tactic="persistence",
            test_name="Create user with useradd",
            command="useradd -M evil_user",
            start_time=start,
            end_time=start + timedelta(seconds=1),
            success=True,
        )
        return BenchmarkRun(
            run_id="test_001",
            start_time=start,
            end_time=start + timedelta(seconds=30),
            attack_results=[result],
        )

    def test_no_baseline_gives_none(self):
        collector = MagicMock(spec=AlertCollector)
        collector.collect_alerts_for_technique.return_value = []

        metrics = MetricsCalculator(collector).calculate_benchmark_metrics(self.make_run())

        assert metrics.false_positive_rate_per_hour is None
        collector.get_alert_rate.assert_not_called()

    def test_baseline_with_no_matches_gives_measured_zero(self):
        collector = MagicMock(spec=AlertCollector)
        collector.collect_alerts_for_technique.return_value = []
        collector.get_alert_rate.return_value = 0.0
        start = datetime(2026, 10, 10, 11, 0, 0)
        window = CollectionWindow(start=start, end=start + timedelta(minutes=5))

        metrics = MetricsCalculator(collector).calculate_benchmark_metrics(
            self.make_run(), baseline_window=window
        )

        assert metrics.false_positive_rate_per_hour == 0.0
        collector.get_alert_rate.assert_called_once()


class TestRecordedReportUnchanged:
    """Regenerating a recorded report changes only the corrected wording."""

    @pytest.fixture
    def recorded(self):
        json_path = RESULTS_DIR / f"{RECORDED_RUN}.json"
        md_path = RESULTS_DIR / f"{RECORDED_RUN}.md"
        if not (json_path.exists() and md_path.exists()):
            pytest.skip("recorded report artifacts not available")
        return json.loads(json_path.read_text()), md_path.read_text()

    def test_json_round_trip_is_identical(self, recorded, tmp_path):
        data, _ = recorded

        regenerated = ReportGenerator(output_dir=tmp_path).generate_json(
            metrics_from_recorded_json(data)
        )

        # These fields were added after this report was recorded. The old file
        # does not say whether its tests were validly evaluated, so the fields
        # are dropped before comparing instead of being read as recorded values.
        added_later = (
            "collection_errors",
            "attack_failures",
            "telemetry_missing",
            "tests_evaluated",
            "status",
        )
        for technique in regenerated["technique_metrics"]:
            for key in added_later:
                technique.pop(key)
        assert regenerated == data

    def test_markdown_keeps_recorded_summary_values(self, recorded, tmp_path):
        data, recorded_md = recorded

        regenerated = ReportGenerator(output_dir=tmp_path).generate_markdown(
            metrics_from_recorded_json(data)
        )

        # The layout and wording have changed since the report was recorded;
        # every recorded summary value must still be rendered as it was.
        summary_rows = [
            line
            for line in recorded_md.split("## Detection by Technique")[0].splitlines()
            if line.startswith("| ") and not line.startswith("| Metric")
        ]
        assert len(summary_rows) == 6
        for row in summary_rows:
            assert row in regenerated


class TestAlertRateMeasurement:
    """get_alert_rate must not turn a failed or invalid measurement into zero."""

    START = datetime(2026, 10, 10, 11, 0, 0)

    @pytest.fixture
    def collector(self):
        with patch("benchmark.collector.Elasticsearch") as mock_es_class:
            mock_es = MagicMock()
            mock_es_class.return_value = mock_es
            collector = AlertCollector()
            collector.es = mock_es
            yield collector

    def window(self, minutes: float) -> CollectionWindow:
        return CollectionWindow(start=self.START, end=self.START + timedelta(minutes=minutes))

    def test_successful_query_with_no_matches_is_measured_zero(self, collector):
        collector.es.count.return_value = {"count": 0}

        assert collector.get_alert_rate(self.window(30), ["useradd"]) == 0.0

    def test_successful_query_with_matches_gives_rate_per_hour(self, collector):
        collector.es.count.return_value = {"count": 6}

        assert collector.get_alert_rate(self.window(30), ["useradd"]) == 12.0

    def test_query_failure_is_unavailable_not_zero(self, collector):
        collector.es.count.side_effect = ConnectionError("Elasticsearch unreachable")

        assert collector.get_alert_rate(self.window(30), ["useradd"]) is None

    def test_empty_window_is_unavailable_not_zero(self, collector):
        assert collector.get_alert_rate(self.window(0), ["useradd"]) is None
        collector.es.count.assert_not_called()

    def test_reversed_window_is_unavailable_not_negative(self, collector):
        assert collector.get_alert_rate(self.window(-5), ["useradd"]) is None
        collector.es.count.assert_not_called()

    def test_query_failure_reaches_report_as_unavailable(self, collector, tmp_path):
        collector.es.count.side_effect = ConnectionError("Elasticsearch unreachable")
        collector.es.search.return_value = {"hits": {"hits": []}}

        metrics = MetricsCalculator(collector).calculate_benchmark_metrics(
            TestFalsePositiveRateCalculation.make_run(), baseline_window=self.window(30)
        )
        generator = ReportGenerator(output_dir=tmp_path)

        assert metrics.false_positive_rate_per_hour is None
        assert "| False Positive Rate | N/A (not measured) |" in generator.generate_markdown(metrics)
        assert generator.generate_json(metrics)["summary"]["false_positive_rate_per_hour"] is None


class TestBaselineRunnerUnavailableRate:
    """run_baseline must report an unavailable rate without crashing or zeroing."""

    def run_with_rate(self, rate):
        start = datetime(2026, 10, 10, 11, 0, 0)
        window = CollectionWindow(start=start, end=start + timedelta(minutes=5))
        with (
            patch("benchmark.baseline.BaselineRunner") as runner_class,
            patch("benchmark.baseline.AlertCollector") as collector_class,
            patch("benchmark.baseline.time.sleep"),
        ):
            runner_class.return_value.run_baseline.return_value = window
            collector_class.return_value.count_logs_in_window.return_value = 10
            collector_class.return_value.get_alert_rate.return_value = rate
            from benchmark.baseline import run_baseline

            return run_baseline(iterations=1)

    def test_unavailable_rate_is_none(self):
        assert self.run_with_rate(None)["detection_alert_rate_per_hour"] is None

    def test_measured_zero_is_kept(self):
        assert self.run_with_rate(0.0)["detection_alert_rate_per_hour"] == 0.0


class TestLogCountMeasurement:
    """count_logs_in_window must not turn a failed query into a zero count."""

    START = datetime(2026, 10, 10, 11, 0, 0)

    @pytest.fixture
    def collector(self):
        with patch("benchmark.collector.Elasticsearch") as mock_es_class:
            mock_es = MagicMock()
            mock_es_class.return_value = mock_es
            collector = AlertCollector()
            collector.es = mock_es
            yield collector

    def window(self, minutes: float) -> CollectionWindow:
        return CollectionWindow(start=self.START, end=self.START + timedelta(minutes=minutes))

    def test_successful_query_with_no_logs_is_measured_zero(self, collector):
        collector.es.count.return_value = {"count": 0}

        count = collector.count_logs_in_window(self.window(5))

        assert count == 0
        assert count is not None

    def test_successful_query_returns_count(self, collector):
        collector.es.count.return_value = {"count": 42}

        assert collector.count_logs_in_window(self.window(5)) == 42

    def test_query_failure_is_unavailable_not_zero(self, collector):
        collector.es.count.side_effect = ConnectionError("Elasticsearch unreachable")

        assert collector.count_logs_in_window(self.window(5)) is None

    def test_invalid_window_is_unavailable_not_zero(self, collector):
        assert collector.count_logs_in_window(self.window(0)) is None
        assert collector.count_logs_in_window(self.window(-5)) is None
        collector.es.count.assert_not_called()


class TestBaselineRunnerLogCount:
    """run_baseline must carry an unavailable log count through without zeroing it."""

    def run_with_count(self, count):
        start = datetime(2026, 10, 10, 11, 0, 0)
        window = CollectionWindow(start=start, end=start + timedelta(minutes=5))
        with (
            patch("benchmark.baseline.BaselineRunner") as runner_class,
            patch("benchmark.baseline.AlertCollector") as collector_class,
            patch("benchmark.baseline.time.sleep"),
        ):
            runner_class.return_value.run_baseline.return_value = window
            collector_class.return_value.count_logs_in_window.return_value = count
            collector_class.return_value.get_alert_rate.return_value = 0.0
            from benchmark.baseline import run_baseline

            return run_baseline(iterations=1)

    def test_unavailable_count_gives_unavailable_rate(self):
        results = self.run_with_count(None)

        assert results["total_logs"] is None
        assert results["logs_per_hour"] is None

    def test_measured_zero_count_is_kept(self):
        results = self.run_with_count(0)

        assert results["total_logs"] == 0
        assert results["logs_per_hour"] == 0.0
        assert results["logs_per_hour"] is not None

    def test_measured_count_gives_rate_per_hour(self):
        results = self.run_with_count(10)

        assert results["total_logs"] == 10
        assert results["logs_per_hour"] == 120.0
