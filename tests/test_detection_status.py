"""Regression tests: a missing alert alone must not be reported as a missed detection."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from benchmark.collector import Alert, AlertCollector, CollectionWindow
from benchmark.metrics import MetricsCalculator
from benchmark.report import ReportGenerator
from benchmark.runner import AttackResult, BenchmarkRun

START = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)


def make_alert() -> Alert:
    return Alert(
        timestamp=START + timedelta(seconds=3),
        rule_id=None,
        rule_name=None,
        log_type="auth",
        technique_id="T1136.001",
        message="useradd[1]: new user: name=evil_user",
        raw={},
    )


def make_result(
    technique_id: str = "T1136.001", name: str = "Local Account", success: bool = True
) -> AttackResult:
    return AttackResult(
        technique_id=technique_id,
        technique_name=name,
        tactic="persistence",
        test_name="test",
        command="true",
        start_time=START,
        end_time=START + timedelta(seconds=1),
        success=success,
    )


def make_collector(alerts, telemetry_count=5) -> MagicMock:
    """Mock collector. alerts / telemetry_count may be a value or a list of values."""
    collector = MagicMock(spec=AlertCollector)
    if isinstance(alerts, list) and alerts and all(a is None or isinstance(a, list) for a in alerts):
        collector.collect_alerts_for_technique.side_effect = alerts
    else:
        collector.collect_alerts_for_technique.return_value = alerts
    if isinstance(telemetry_count, list):
        collector.count_logs_in_window.side_effect = telemetry_count
    else:
        collector.count_logs_in_window.return_value = telemetry_count
    return collector


def technique_metrics(collector, results=None, technique_id="T1136.001"):
    return MetricsCalculator(collector).calculate_technique_metrics(
        technique_id, results or [make_result(technique_id)]
    )


def benchmark_metrics(collector, results):
    run = BenchmarkRun(
        run_id="test_001",
        start_time=START,
        end_time=START + timedelta(seconds=30),
        attack_results=results,
    )
    return MetricsCalculator(collector).calculate_benchmark_metrics(run)


class TestTechniqueStatus:
    def test_detected_when_valid_run_has_matching_alert(self):
        collector = make_collector([make_alert()])

        metrics = technique_metrics(collector)

        assert metrics.status == "DETECTED"
        assert metrics.tests_evaluated == 1
        assert metrics.detection_rate == 1.0
        collector.count_logs_in_window.assert_not_called()

    def test_not_detected_when_log_source_was_producing_events(self):
        metrics = technique_metrics(make_collector([], telemetry_count=5))

        assert metrics.status == "NOT DETECTED"
        assert metrics.tests_evaluated == 1
        assert metrics.false_negative_count == 1
        assert metrics.detection_rate == 0.0
        assert metrics.telemetry_missing == 0

    def test_not_evaluated_when_log_source_produced_no_events(self):
        metrics = technique_metrics(make_collector([], telemetry_count=0))

        assert metrics.status == "NOT EVALUATED"
        assert metrics.telemetry_missing == 1
        assert metrics.tests_evaluated == 0
        assert metrics.false_negative_count == 0
        assert metrics.detection_rate is None

    def test_not_evaluated_when_alert_query_fails(self):
        metrics = technique_metrics(make_collector([None]))

        assert metrics.status == "NOT EVALUATED"
        assert metrics.collection_errors == 1
        assert metrics.false_negative_count == 0
        assert metrics.detection_rate is None

    def test_not_evaluated_when_telemetry_query_fails(self):
        metrics = technique_metrics(make_collector([], telemetry_count=None))

        assert metrics.status == "NOT EVALUATED"
        assert metrics.collection_errors == 1
        assert metrics.telemetry_missing == 0
        assert metrics.false_negative_count == 0

    def test_not_evaluated_when_attack_command_failed(self):
        collector = make_collector([])

        metrics = technique_metrics(collector, [make_result(success=False)])

        assert metrics.status == "NOT EVALUATED"
        assert metrics.attack_failures == 1
        assert metrics.false_negative_count == 0
        assert metrics.detection_rate is None
        collector.collect_alerts_for_technique.assert_not_called()

    def test_rate_uses_only_evaluated_tests(self):
        collector = make_collector([[make_alert()], [], []], telemetry_count=[0, 3])

        metrics = technique_metrics(collector, [make_result(), make_result(), make_result()])

        assert metrics.tests_executed == 3
        assert metrics.tests_evaluated == 2
        assert metrics.telemetry_missing == 1
        assert metrics.false_negative_count == 1
        assert metrics.detection_rate == 0.5
        assert metrics.status == "DETECTED"

    def test_telemetry_check_uses_expected_log_sources(self):
        collector = make_collector([], telemetry_count=0)

        technique_metrics(collector, technique_id="T1059.004")

        assert collector.count_logs_in_window.call_args.kwargs["log_types"] == ["auditd"]

    def test_telemetry_check_includes_sources_that_carried_evidence(self):
        collector = make_collector([], telemetry_count=0)

        technique_metrics(collector, technique_id="T1053.003")

        log_types = collector.count_logs_in_window.call_args.kwargs["log_types"]
        assert set(log_types) == {"auditd", "cron", "syslog"}


class TestBenchmarkStatus:
    def test_unevaluated_technique_is_not_a_detection_gap(self):
        collector = make_collector([[], []], telemetry_count=[0, 4])

        metrics = benchmark_metrics(
            collector, [make_result("T1059.004", "Unix Shell"), make_result("T1082", "System Info")]
        )

        assert metrics.detection_gaps == ["T1082 (System Info)"]
        assert metrics.overall_detection_rate == 0.0

    def test_all_unevaluated_gives_unavailable_overall_rate(self):
        metrics = benchmark_metrics(make_collector([], telemetry_count=0), [make_result()])

        assert metrics.overall_detection_rate is None
        assert metrics.detection_gaps == []


class TestReportStatus:
    @staticmethod
    def three_outcomes():
        collector = make_collector([[make_alert()], [], []], telemetry_count=[4, 0])
        return benchmark_metrics(
            collector,
            [
                make_result("T1136.001", "Local Account"),
                make_result("T1082", "System Info"),
                make_result("T1059.004", "Unix Shell"),
            ],
        )

    def test_markdown_shows_all_three_statuses(self, tmp_path):
        md = ReportGenerator(output_dir=tmp_path).generate_markdown(self.three_outcomes())

        assert "| T1136.001 (Local Account) | persistence | 1 | 1 | 1 | DETECTED | 100% |" in md
        assert "| T1082 (System Info) | persistence | 1 | 1 | 0 | NOT DETECTED | 0% |" in md
        assert "| T1059.004 (Unix Shell) | persistence | 1 | 0 | 0 | NOT EVALUATED | N/A |" in md

    def test_markdown_lists_unevaluated_technique_with_reason(self, tmp_path):
        md = ReportGenerator(output_dir=tmp_path).generate_markdown(self.three_outcomes())

        assert "## Not Evaluated" in md
        assert (
            "- T1059.004 (Unix Shell): 1 of 1 tests "
            "(no events from the expected log source: 1)" in md
        )

    def test_markdown_lists_only_evaluated_misses_as_not_detected(self, tmp_path):
        md = ReportGenerator(output_dir=tmp_path).generate_markdown(self.three_outcomes())

        not_detected = md.split("## Not Detected")[1].split("## Not Evaluated")[0]
        assert "- T1082 (System Info)" in not_detected
        assert "T1059.004" not in not_detected

    def test_markdown_drops_old_gap_wording(self, tmp_path):
        md = ReportGenerator(output_dir=tmp_path).generate_markdown(self.three_outcomes())

        assert "Detection Gaps" not in md
        assert "0% detection rate" not in md

    def test_markdown_reports_other_reasons(self, tmp_path):
        collector = make_collector([None])
        metrics = benchmark_metrics(
            collector, [make_result(), make_result("T1105", "Ingress Tool Transfer", success=False)]
        )

        md = ReportGenerator(output_dir=tmp_path).generate_markdown(metrics)

        assert "- T1136.001 (Local Account): 1 of 1 tests (Elasticsearch query failed: 1)" in md
        assert (
            "- T1105 (Ingress Tool Transfer): 1 of 1 tests (attack command failed: 1)" in md
        )

    def test_json_reports_status_and_counts(self, tmp_path):
        report = ReportGenerator(output_dir=tmp_path).generate_json(self.three_outcomes())

        by_id = {t["technique_id"]: t for t in report["technique_metrics"]}
        assert by_id["T1136.001"]["status"] == "DETECTED"
        assert by_id["T1082"]["status"] == "NOT DETECTED"
        assert by_id["T1059.004"]["status"] == "NOT EVALUATED"
        assert by_id["T1059.004"]["tests_evaluated"] == 0
        assert by_id["T1059.004"]["telemetry_missing"] == 1
        assert by_id["T1059.004"]["detection_rate"] is None
        assert report["detection_gaps"] == ["T1082 (System Info)"]

    def test_console_summary_handles_all_statuses(self, tmp_path):
        # Must not raise
        ReportGenerator(output_dir=tmp_path).print_summary(self.three_outcomes())


class TestTypedLogCount:
    START = datetime(2026, 10, 10, 11, 0, 0)

    @pytest.fixture
    def collector(self):
        with patch("benchmark.collector.Elasticsearch") as mock_es_class:
            mock_es = MagicMock()
            mock_es_class.return_value = mock_es
            collector = AlertCollector()
            collector.es = mock_es
            yield collector

    def window(self) -> CollectionWindow:
        return CollectionWindow(start=self.START, end=self.START + timedelta(seconds=16))

    def test_log_types_are_added_as_a_filter(self, collector):
        collector.es.count.return_value = {"count": 0}

        assert collector.count_logs_in_window(self.window(), log_types=["auditd"]) == 0

        query = collector.es.count.call_args.kwargs["query"]
        assert query["bool"]["filter"] == [{"terms": {"log_type": ["auditd"]}}]

    def test_query_without_log_types_is_unchanged(self, collector):
        collector.es.count.return_value = {"count": 7}

        assert collector.count_logs_in_window(self.window()) == 7
        assert "range" in collector.es.count.call_args.kwargs["query"]
