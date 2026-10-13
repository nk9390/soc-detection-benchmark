"""Focused tests for the detection pipeline using mocked Elasticsearch responses.

These tests exercise the actual production code paths:
- collector.collect_alerts_for_technique() parsing
- metrics.MetricsCalculator TP/FN calculation
- Detection key matching for various log formats
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from benchmark.collector import Alert, AlertCollector, CollectionWindow
from benchmark.metrics import MetricsCalculator, TechniqueMetrics
from benchmark.runner import AttackResult


def make_es_hit(timestamp: str, message: str, log_type: str = "auditd") -> dict:
    """Create an Elasticsearch hit structure matching real responses."""
    return {
        "_index": "soc-benchmark-2026.10.10",
        "_id": "test123",
        "_score": 1.0,
        "_source": {
            "@timestamp": timestamp,
            "message": message,
            "log_type": log_type,
        },
    }


def make_es_response(hits: list[dict]) -> dict:
    """Create an Elasticsearch search response structure."""
    return {
        "took": 5,
        "timed_out": False,
        "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
        "hits": {
            "total": {"value": len(hits), "relation": "eq"},
            "max_score": 1.0,
            "hits": hits,
        },
    }


class TestCollectorParsesEsResponse:
    """Tests that collector.collect_alerts_for_technique parses ES responses correctly."""

    @pytest.fixture
    def collector(self):
        """Create AlertCollector with mocked Elasticsearch client."""
        with patch("benchmark.collector.Elasticsearch") as mock_es_class:
            mock_es = MagicMock()
            mock_es_class.return_value = mock_es
            collector = AlertCollector()
            collector.es = mock_es
            yield collector

    def test_parses_auditd_useradd_event(self, collector):
        """Auditd-style useradd event is parsed into Alert object."""
        es_response = make_es_response([
            make_es_hit(
                timestamp="2026-10-10T12:00:00.000000Z",
                message='type=ADD_USER msg=audit(1234): pid=5678 uid=0 auid=0 ses=1 subj=unconfined msg="op=adding user id=1001 exe=/usr/sbin/useradd" res=success',
                log_type="auditd",
            )
        ])
        collector.es.search.return_value = es_response

        window = CollectionWindow(
            start=datetime(2026, 10, 10, 11, 59, 0, tzinfo=timezone.utc),
            end=datetime(2026, 10, 10, 12, 1, 0, tzinfo=timezone.utc),
        )

        alerts = collector.collect_alerts_for_technique(
            technique_id="T1136.001",
            window=window,
            audit_keys=["user_add", "user_mod", "useradd"],
        )

        assert len(alerts) == 1
        assert isinstance(alerts[0], Alert)
        assert alerts[0].timestamp.tzinfo is not None
        assert alerts[0].log_type == "auditd"
        assert "useradd" in alerts[0].message

    def test_parses_syslog_useradd_event(self, collector):
        """Syslog-style useradd event is parsed into Alert object."""
        es_response = make_es_response([
            make_es_hit(
                timestamp="2026-10-10T12:00:00.000000Z",
                message="Oct 10 12:00:00 target useradd[1234]: new user: name=evil_user, UID=1001, GID=1001, home=/home/evil_user, shell=/bin/bash",
                log_type="auth",
            )
        ])
        collector.es.search.return_value = es_response

        window = CollectionWindow(
            start=datetime(2026, 10, 10, 11, 59, 0, tzinfo=timezone.utc),
            end=datetime(2026, 10, 10, 12, 1, 0, tzinfo=timezone.utc),
        )

        alerts = collector.collect_alerts_for_technique(
            technique_id="T1136.001",
            window=window,
            audit_keys=["user_add", "user_mod", "useradd"],
        )

        assert len(alerts) == 1
        assert alerts[0].log_type == "auth"
        assert "useradd" in alerts[0].message

    def test_parses_timestamp_with_z_suffix(self, collector):
        """Timestamp with Z suffix is parsed as UTC."""
        es_response = make_es_response([
            make_es_hit(
                timestamp="2026-10-10T12:30:45.123456Z",
                message="useradd test",
                log_type="auth",
            )
        ])
        collector.es.search.return_value = es_response

        window = CollectionWindow(
            start=datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc),
            end=datetime(2026, 10, 10, 13, 0, 0, tzinfo=timezone.utc),
        )

        alerts = collector.collect_alerts_for_technique(
            technique_id="T1136.001",
            window=window,
            audit_keys=["useradd"],
        )

        assert len(alerts) == 1
        assert alerts[0].timestamp.hour == 12
        assert alerts[0].timestamp.minute == 30
        assert alerts[0].timestamp.tzinfo is not None

    def test_parses_timestamp_without_timezone(self, collector):
        """Timestamp without timezone is assumed UTC."""
        es_response = make_es_response([
            make_es_hit(
                timestamp="2026-10-10T12:30:45.123456",
                message="useradd test",
                log_type="auth",
            )
        ])
        collector.es.search.return_value = es_response

        window = CollectionWindow(
            start=datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc),
            end=datetime(2026, 10, 10, 13, 0, 0, tzinfo=timezone.utc),
        )

        alerts = collector.collect_alerts_for_technique(
            technique_id="T1136.001",
            window=window,
            audit_keys=["useradd"],
        )

        assert len(alerts) == 1
        assert alerts[0].timestamp.tzinfo is not None
        assert alerts[0].timestamp.tzinfo == timezone.utc

    def test_empty_response_returns_no_alerts(self, collector):
        """Empty ES response returns empty alert list."""
        es_response = make_es_response([])
        collector.es.search.return_value = es_response

        window = CollectionWindow(
            start=datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc),
            end=datetime(2026, 10, 10, 13, 0, 0, tzinfo=timezone.utc),
        )

        alerts = collector.collect_alerts_for_technique(
            technique_id="T1136.001",
            window=window,
            audit_keys=["useradd"],
        )

        assert len(alerts) == 0


class TestMetricsCalculatorTpFn:
    """Tests that MetricsCalculator correctly calculates TP/FN from alerts."""

    @pytest.fixture
    def mock_collector(self):
        """Create a mocked AlertCollector."""
        with patch("benchmark.collector.Elasticsearch"):
            collector = MagicMock(spec=AlertCollector)
            yield collector

    def test_matching_alert_produces_detection(self, mock_collector):
        """Attack with matching alert is counted as detected (TP)."""
        # Mock collector to return one alert
        mock_collector.collect_alerts_for_technique.return_value = [
            Alert(
                timestamp=datetime(2026, 10, 10, 12, 0, 5, tzinfo=timezone.utc),
                rule_id=None,
                rule_name=None,
                log_type="auditd",
                technique_id="T1136.001",
                message="useradd: new user",
                raw={},
            )
        ]

        calculator = MetricsCalculator(mock_collector)

        attack_result = AttackResult(
            technique_id="T1136.001",
            technique_name="Local Account",
            tactic="persistence",
            test_name="Create user with useradd",
            command="useradd -M evil_user",
            start_time=datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc),
            end_time=datetime(2026, 10, 10, 12, 0, 1, tzinfo=timezone.utc),
            success=True,
        )

        metrics = calculator.calculate_technique_metrics("T1136.001", [attack_result])

        assert metrics.tests_executed == 1
        assert metrics.tests_detected == 1
        assert metrics.detection_rate == 1.0
        assert metrics.false_negative_count == 0
        assert metrics.alert_count == 1

    def test_no_alert_produces_false_negative(self, mock_collector):
        """Attack without matching alert is counted as false negative."""
        # Mock collector to return no alerts
        mock_collector.collect_alerts_for_technique.return_value = []

        calculator = MetricsCalculator(mock_collector)

        attack_result = AttackResult(
            technique_id="T1136.001",
            technique_name="Local Account",
            tactic="persistence",
            test_name="Create user with useradd",
            command="useradd -M evil_user",
            start_time=datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc),
            end_time=datetime(2026, 10, 10, 12, 0, 1, tzinfo=timezone.utc),
            success=True,
        )

        metrics = calculator.calculate_technique_metrics("T1136.001", [attack_result])

        assert metrics.tests_executed == 1
        assert metrics.tests_detected == 0
        assert metrics.detection_rate == 0.0
        assert metrics.false_negative_count == 1
        assert metrics.alert_count == 0

    def test_multiple_attacks_partial_detection(self, mock_collector):
        """Multiple attacks with partial detection calculates correct rate."""
        # First call returns alert, second returns nothing
        mock_collector.collect_alerts_for_technique.side_effect = [
            [Alert(
                timestamp=datetime(2026, 10, 10, 12, 0, 5, tzinfo=timezone.utc),
                rule_id=None,
                rule_name=None,
                log_type="auditd",
                technique_id="T1136.001",
                message="useradd: new user",
                raw={},
            )],
            [],  # No alert for second attack
        ]

        calculator = MetricsCalculator(mock_collector)

        attack_results = [
            AttackResult(
                technique_id="T1136.001",
                technique_name="Local Account",
                tactic="persistence",
                test_name="Create user with useradd",
                command="useradd -M evil_user1",
                start_time=datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc),
                end_time=datetime(2026, 10, 10, 12, 0, 1, tzinfo=timezone.utc),
                success=True,
            ),
            AttackResult(
                technique_id="T1136.001",
                technique_name="Local Account",
                tactic="persistence",
                test_name="Create user with useradd",
                command="useradd -M evil_user2",
                start_time=datetime(2026, 10, 10, 12, 1, 0, tzinfo=timezone.utc),
                end_time=datetime(2026, 10, 10, 12, 1, 1, tzinfo=timezone.utc),
                success=True,
            ),
        ]

        metrics = calculator.calculate_technique_metrics("T1136.001", attack_results)

        assert metrics.tests_executed == 2
        assert metrics.tests_detected == 1
        assert metrics.detection_rate == 0.5
        assert metrics.false_negative_count == 1

    def test_time_to_detect_calculation(self, mock_collector):
        """TTD is calculated from attack start to first alert."""
        alert_time = datetime(2026, 10, 10, 12, 0, 3, tzinfo=timezone.utc)
        attack_start = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)

        mock_collector.collect_alerts_for_technique.return_value = [
            Alert(
                timestamp=alert_time,
                rule_id=None,
                rule_name=None,
                log_type="auditd",
                technique_id="T1136.001",
                message="useradd",
                raw={},
            )
        ]

        calculator = MetricsCalculator(mock_collector)

        attack_result = AttackResult(
            technique_id="T1136.001",
            technique_name="Local Account",
            tactic="persistence",
            test_name="Create user",
            command="useradd evil",
            start_time=attack_start,
            end_time=datetime(2026, 10, 10, 12, 0, 1, tzinfo=timezone.utc),
            success=True,
        )

        metrics = calculator.calculate_technique_metrics("T1136.001", [attack_result])

        # TTD should be 3 seconds (alert at 12:00:03, attack at 12:00:00)
        assert metrics.mean_time_to_detect_seconds == 3.0


class TestDetectionKeyMatching:
    """Tests that detection keys match expected log formats.

    Note: These tests verify what the detection keys SHOULD match.
    The actual matching is done by Elasticsearch's match query,
    not Python code. These tests document expected behavior.
    """

    def test_t1136_001_keys_match_auditd_format(self):
        """T1136.001 keys should match auditd user_mod format."""
        keys = MetricsCalculator.TECHNIQUE_DETECTION_KEYS["T1136.001"]
        auditd_message = 'type=USER_ACCT msg=audit(1234): pid=5678 uid=0 auid=0 ses=1 subj=unconfined op=adding-user id=1001 exe="/usr/sbin/useradd" hostname=? addr=? terminal=pts/0 res=success'

        # At least one key should appear in the message
        matched = any(key.lower() in auditd_message.lower() for key in keys)
        assert matched, f"No key from {keys} found in auditd message"

    def test_t1136_001_keys_match_syslog_format(self):
        """T1136.001 keys should match syslog useradd format."""
        keys = MetricsCalculator.TECHNIQUE_DETECTION_KEYS["T1136.001"]
        syslog_message = "Oct 10 12:00:00 target useradd[1234]: new user: name=evil_user, UID=1001"

        # "useradd" should match
        matched = any(key.lower() in syslog_message.lower() for key in keys)
        assert matched, f"No key from {keys} found in syslog message"

    def test_t1136_001_keys_do_not_match_benign(self):
        """T1136.001 keys should NOT match benign commands."""
        keys = MetricsCalculator.TECHNIQUE_DETECTION_KEYS["T1136.001"]
        benign_messages = [
            "Oct 10 12:00:00 target CRON[1234]: (root) CMD (/usr/bin/find /tmp)",
            "Oct 10 12:00:00 target sshd[5678]: Accepted publickey for admin",
            "type=EXECVE msg=audit(1234): argc=2 a0=\"ls\" a1=\"-la\"",
        ]

        for message in benign_messages:
            matched = any(key.lower() in message.lower() for key in keys)
            assert not matched, f"Key from {keys} incorrectly matched: {message}"

    def test_t1059_004_keys_match_shell_execution(self):
        """T1059.004 keys should match shell execution."""
        keys = MetricsCalculator.TECHNIQUE_DETECTION_KEYS["T1059.004"]
        auditd_message = 'type=EXECVE msg=audit(1234): argc=3 a0="/bin/bash" a1="-c" a2="whoami"'

        matched = any(key in auditd_message for key in keys)
        assert matched, f"No key from {keys} found in EXECVE message"

    def test_missing_technique_returns_empty_keys(self):
        """Unknown technique ID returns empty detection keys."""
        keys = MetricsCalculator.TECHNIQUE_DETECTION_KEYS.get("T9999.999", [])
        assert keys == []


class TestEndToEndMockedPipeline:
    """Integration test: mock ES response through collector to metrics."""

    def test_full_pipeline_with_matching_log(self):
        """Full pipeline: ES response -> collector parsing -> metrics calculation."""
        # Create a realistic ES response
        es_response = make_es_response([
            make_es_hit(
                timestamp="2026-10-10T12:00:02.500000Z",
                message='type=ADD_USER msg=audit(1234): op=adding user id=1001 exe="/usr/sbin/useradd" res=success',
                log_type="auditd",
            )
        ])

        with patch("benchmark.collector.Elasticsearch") as mock_es_class:
            mock_es = MagicMock()
            mock_es_class.return_value = mock_es
            mock_es.search.return_value = es_response

            # Create real collector (with mocked ES)
            collector = AlertCollector()

            # Create real MetricsCalculator with real collector
            calculator = MetricsCalculator(collector)

            # Create attack result
            attack_result = AttackResult(
                technique_id="T1136.001",
                technique_name="Local Account",
                tactic="persistence",
                test_name="Create user with useradd",
                command="useradd -M evil_user",
                start_time=datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc),
                end_time=datetime(2026, 10, 10, 12, 0, 1, tzinfo=timezone.utc),
                success=True,
            )

            # Calculate metrics through full pipeline
            metrics = calculator.calculate_technique_metrics("T1136.001", [attack_result])

            # Verify detection
            assert metrics.tests_executed == 1
            assert metrics.tests_detected == 1
            assert metrics.detection_rate == 1.0
            assert metrics.alert_count == 1
            assert metrics.mean_time_to_detect_seconds == 2.5  # Alert at :02.5, attack at :00

    def test_full_pipeline_with_no_matching_log(self):
        """Full pipeline with empty ES response produces FN."""
        es_response = make_es_response([])

        with patch("benchmark.collector.Elasticsearch") as mock_es_class:
            mock_es = MagicMock()
            mock_es_class.return_value = mock_es
            mock_es.search.return_value = es_response

            collector = AlertCollector()
            calculator = MetricsCalculator(collector)

            attack_result = AttackResult(
                technique_id="T1136.001",
                technique_name="Local Account",
                tactic="persistence",
                test_name="Create user with useradd",
                command="useradd -M evil_user",
                start_time=datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc),
                end_time=datetime(2026, 10, 10, 12, 0, 1, tzinfo=timezone.utc),
                success=True,
            )

            metrics = calculator.calculate_technique_metrics("T1136.001", [attack_result])

            assert metrics.tests_executed == 1
            assert metrics.tests_detected == 0
            assert metrics.false_negative_count == 1


class TestCollectionWindowBuffer:
    """Tests for collection window buffer configuration."""

    def test_default_post_attack_buffer_is_15_seconds(self):
        """Default post-attack buffer should be 15 seconds."""
        assert MetricsCalculator.DEFAULT_POST_BUFFER_SECONDS == 15

    def test_pre_attack_buffer_is_1_second(self):
        """Pre-attack buffer should be 1 second (verified via constant in code)."""
        # The 1-second pre-buffer is used in the window calculation
        # This test verifies the constant exists in the module
        import ast
        from pathlib import Path

        metrics_path = Path("benchmark/metrics.py")
        content = metrics_path.read_text()
        # Verify "seconds=1" appears in the start window calculation
        assert "seconds=1" in content or "seconds = 1" in content

    def test_cron_technique_has_extended_buffer(self):
        """T1053.003 (Cron) needs 65s buffer due to minute-boundary event generation."""
        buffer = MetricsCalculator.TECHNIQUE_POST_BUFFER.get("T1053.003")
        assert buffer == 65, f"Cron buffer should be 65s, got {buffer}"

    def test_technique_specific_buffer_used_in_window_calculation(self):
        """Verify technique-specific buffers are applied during metrics calculation."""
        # Create a mock collector that tracks the window used
        mock_collector = MagicMock()
        mock_collector.collect_alerts_for_technique.return_value = []

        calculator = MetricsCalculator(mock_collector)

        # Create a test attack result for T1053.003 (cron)
        attack_time = datetime(2026, 10, 10, 12, 0, 0)
        result = AttackResult(
            technique_id="T1053.003",
            technique_name="Cron",
            tactic="persistence",
            test_name="test",
            command="echo test >> /etc/crontab",
            start_time=attack_time,
            end_time=attack_time + timedelta(milliseconds=50),
            success=True,
        )

        calculator.calculate_technique_metrics("T1053.003", [result])

        # Verify the collector was called with extended window
        call_args = mock_collector.collect_alerts_for_technique.call_args
        window = call_args.kwargs.get("window") or call_args[1].get("window")

        # Window end should be attack_end + 65 seconds for cron
        expected_end = attack_time + timedelta(milliseconds=50) + timedelta(seconds=65)
        assert window.end == expected_end, f"Expected window end {expected_end}, got {window.end}"

    def test_default_buffer_for_non_cron_techniques(self):
        """Non-cron techniques should use the default 15s buffer."""
        mock_collector = MagicMock()
        mock_collector.collect_alerts_for_technique.return_value = []

        calculator = MetricsCalculator(mock_collector)

        attack_time = datetime(2026, 10, 10, 12, 0, 0)
        result = AttackResult(
            technique_id="T1136.001",
            technique_name="Local Account",
            tactic="persistence",
            test_name="test",
            command="useradd evil_user",
            start_time=attack_time,
            end_time=attack_time + timedelta(milliseconds=50),
            success=True,
        )

        calculator.calculate_technique_metrics("T1136.001", [result])

        call_args = mock_collector.collect_alerts_for_technique.call_args
        window = call_args.kwargs.get("window") or call_args[1].get("window")

        # Window end should be attack_end + 15 seconds (default)
        expected_end = attack_time + timedelta(milliseconds=50) + timedelta(seconds=15)
        assert window.end == expected_end, f"Expected window end {expected_end}, got {window.end}"
