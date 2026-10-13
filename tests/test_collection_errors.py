"""Regression tests: failed Elasticsearch queries are not zero logs or missed detections."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from benchmark.collector import Alert, AlertCollector, CollectionWindow
from benchmark.metrics import MetricsCalculator
from benchmark.report import ReportGenerator
from benchmark.runner import AttackResult, BenchmarkRun

START = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)
WINDOW = CollectionWindow(start=START, end=START + timedelta(seconds=16))


def make_hit(message: str) -> dict:
    return {
        "_source": {
            "@timestamp": "2026-10-10T12:00:03.000Z",
            "message": message,
            "log_type": "auth",
        }
    }


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


def make_result(technique_id: str = "T1136.001", name: str = "Local Account") -> AttackResult:
    return AttackResult(
        technique_id=technique_id,
        technique_name=name,
        tactic="persistence",
        test_name="test",
        command="true",
        start_time=START,
        end_time=START + timedelta(seconds=1),
        success=True,
    )


@pytest.fixture
def collector():
    with patch("benchmark.collector.Elasticsearch") as mock_es_class:
        mock_es = MagicMock()
        mock_es_class.return_value = mock_es
        collector = AlertCollector()
        collector.es = mock_es
        yield collector


class TestCollectLogs:
    def test_successful_empty_result_is_empty_list(self, collector):
        collector.es.search.return_value = {"hits": {"hits": []}}

        assert collector.collect_logs(WINDOW) == []

    def test_successful_result_returns_documents(self, collector):
        collector.es.search.return_value = {"hits": {"hits": [make_hit("a"), make_hit("b")]}}

        logs = collector.collect_logs(WINDOW)

        assert [log["message"] for log in logs] == ["a", "b"]

    def test_query_failure_is_unavailable_not_empty(self, collector):
        collector.es.search.side_effect = ConnectionError("Elasticsearch unreachable")

        assert collector.collect_logs(WINDOW) is None


class TestCollectAlertsForTechnique:
    def test_successful_empty_result_is_empty_list(self, collector):
        collector.es.search.return_value = {"hits": {"hits": []}}

        assert collector.collect_alerts_for_technique("T1136.001", WINDOW, ["useradd"]) == []

    def test_successful_result_returns_alerts(self, collector):
        collector.es.search.return_value = {"hits": {"hits": [make_hit("useradd evil_user")]}}

        alerts = collector.collect_alerts_for_technique("T1136.001", WINDOW, ["useradd"])

        assert len(alerts) == 1
        assert alerts[0].message == "useradd evil_user"

    def test_query_failure_is_unavailable_not_empty(self, collector):
        collector.es.search.side_effect = ConnectionError("Elasticsearch unreachable")

        assert collector.collect_alerts_for_technique("T1136.001", WINDOW, ["useradd"]) is None


class TestTechniqueMetricsWithCollectionErrors:
    @staticmethod
    def calculate(side_effect, results=None):
        mock_collector = MagicMock(spec=AlertCollector)
        mock_collector.collect_alerts_for_technique.side_effect = side_effect
        return MetricsCalculator(mock_collector).calculate_technique_metrics(
            "T1136.001", results or [make_result()]
        )

    def test_query_failure_is_not_a_false_negative(self):
        metrics = self.calculate([None])

        assert metrics.tests_executed == 1
        assert metrics.collection_errors == 1
        assert metrics.tests_detected == 0
        assert metrics.false_negative_count == 0
        assert metrics.detection_rate is None

    def test_successful_empty_result_is_a_false_negative(self):
        metrics = self.calculate([[]])

        assert metrics.collection_errors == 0
        assert metrics.false_negative_count == 1
        assert metrics.detection_rate == 0.0

    def test_successful_match_is_a_detection(self):
        metrics = self.calculate([[make_alert()]])

        assert metrics.collection_errors == 0
        assert metrics.tests_detected == 1
        assert metrics.detection_rate == 1.0

    def test_rate_is_computed_over_evaluated_tests_only(self):
        metrics = self.calculate(
            [[make_alert()], None, []], [make_result(), make_result(), make_result()]
        )

        assert metrics.tests_executed == 3
        assert metrics.collection_errors == 1
        assert metrics.tests_detected == 1
        assert metrics.false_negative_count == 1
        assert metrics.detection_rate == 0.5


class TestBenchmarkMetricsWithCollectionErrors:
    @staticmethod
    def calculate(side_effect, results):
        mock_collector = MagicMock(spec=AlertCollector)
        mock_collector.collect_alerts_for_technique.side_effect = side_effect
        run = BenchmarkRun(
            run_id="test_001",
            start_time=START,
            end_time=START + timedelta(seconds=30),
            attack_results=results,
        )
        return MetricsCalculator(mock_collector).calculate_benchmark_metrics(run)

    def test_all_queries_failed_gives_unavailable_rates(self):
        metrics = self.calculate([None], [make_result()])

        assert metrics.total_attacks == 1
        assert metrics.total_detected == 0
        assert metrics.overall_detection_rate is None
        assert metrics.alert_volume_per_attack is None
        assert metrics.detection_gaps == []

    def test_failed_technique_is_not_a_detection_gap(self):
        metrics = self.calculate(
            [None, []], [make_result(), make_result("T1053.003", "Cron")]
        )

        assert metrics.overall_detection_rate == 0.0
        assert metrics.detection_gaps == ["T1053.003 (Cron)"]

    def test_no_failures_is_unchanged(self):
        metrics = self.calculate([[make_alert()]], [make_result()])

        assert metrics.overall_detection_rate == 1.0
        assert metrics.alert_volume_per_attack == 1.0
        assert metrics.technique_metrics[0].collection_errors == 0


class TestReportWithCollectionErrors:
    @staticmethod
    def metrics(side_effect, results):
        return TestBenchmarkMetricsWithCollectionErrors.calculate(side_effect, results)

    def test_markdown_marks_failed_technique_as_unavailable(self, tmp_path):
        md = ReportGenerator(output_dir=tmp_path).generate_markdown(
            self.metrics([None], [make_result()])
        )

        assert "| **Overall Detection Rate** | **N/A** |" in md
        assert "| T1136.001 (Local Account) | persistence | 1 | 0 | 0 | NOT EVALUATED | N/A | N/A |" in md
        assert "## Not Evaluated" in md
        assert "- T1136.001 (Local Account): 1 of 1 tests (Elasticsearch query failed: 1)" in md
        assert "0% detection rate" not in md

    def test_markdown_has_no_error_section_without_failures(self, tmp_path):
        md = ReportGenerator(output_dir=tmp_path).generate_markdown(
            self.metrics([[make_alert()]], [make_result()])
        )

        assert "## Not Evaluated" not in md
        assert "| T1136.001 (Local Account) | persistence | 1 | 1 | 1 | DETECTED | 100% |" in md

    def test_json_reports_collection_errors_and_null_rate(self, tmp_path):
        report = ReportGenerator(output_dir=tmp_path).generate_json(
            self.metrics([None], [make_result()])
        )

        assert report["summary"]["overall_detection_rate"] is None
        assert report["technique_metrics"][0]["collection_errors"] == 1
        assert report["technique_metrics"][0]["detection_rate"] is None
        assert report["technique_metrics"][0]["false_negative_count"] == 0

    def test_console_summary_handles_unavailable_rates(self, tmp_path):
        # Must not raise when rates are unavailable
        ReportGenerator(output_dir=tmp_path).print_summary(self.metrics([None], [make_result()]))
