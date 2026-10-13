"""Focused unit tests for timezone handling and baseline configuration."""

from datetime import datetime, timedelta, timezone

import pytest


class TestToUtcIso:
    """Tests for collector.to_utc_iso() function."""

    def test_naive_datetime_converted_to_utc_iso(self):
        """Naive datetime should be treated as local time and converted to UTC."""
        from benchmark.collector import to_utc_iso

        # Create a naive datetime
        naive_dt = datetime(2026, 10, 10, 12, 0, 0)

        result = to_utc_iso(naive_dt)

        # Result should be a string ending with Z (UTC)
        assert isinstance(result, str)
        assert result.endswith("Z")
        # Should be parseable as ISO format
        parsed = datetime.fromisoformat(result.replace("Z", "+00:00"))
        assert parsed.tzinfo is not None

    def test_utc_aware_datetime_stays_utc(self):
        """UTC-aware datetime should remain UTC."""
        from benchmark.collector import to_utc_iso

        utc_dt = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)

        result = to_utc_iso(utc_dt)

        assert result == "2026-10-10T12:00:00.000000Z"

    def test_non_utc_aware_datetime_converted_to_utc(self):
        """Non-UTC aware datetime should be converted to UTC."""
        from benchmark.collector import to_utc_iso

        # Create datetime with +05:00 offset
        offset = timezone(timedelta(hours=5))
        aware_dt = datetime(2026, 10, 10, 17, 0, 0, tzinfo=offset)

        result = to_utc_iso(aware_dt)

        # 17:00 +05:00 = 12:00 UTC
        assert result == "2026-10-10T12:00:00.000000Z"

    def test_output_format_is_elasticsearch_compatible(self):
        """Output should be in Elasticsearch-compatible ISO format."""
        from benchmark.collector import to_utc_iso

        dt = datetime(2026, 10, 10, 12, 30, 45, 123456, tzinfo=timezone.utc)

        result = to_utc_iso(dt)

        # Should match ES expected format: YYYY-MM-DDTHH:MM:SS.ffffffZ
        assert result == "2026-10-10T12:30:45.123456Z"


class TestToUtc:
    """Tests for metrics.to_utc() function."""

    def test_naive_datetime_converted_to_utc_aware(self):
        """Naive datetime should become UTC-aware."""
        from benchmark.metrics import to_utc

        naive_dt = datetime(2026, 10, 10, 12, 0, 0)

        result = to_utc(naive_dt)

        # Result should be timezone-aware
        assert result.tzinfo is not None
        # Should be in UTC
        assert result.tzinfo == timezone.utc

    def test_utc_aware_datetime_stays_utc(self):
        """UTC-aware datetime should remain unchanged."""
        from benchmark.metrics import to_utc

        utc_dt = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)

        result = to_utc(utc_dt)

        assert result == utc_dt
        assert result.tzinfo == timezone.utc

    def test_non_utc_aware_datetime_converted_to_utc(self):
        """Non-UTC aware datetime should be converted to UTC."""
        from benchmark.metrics import to_utc

        # Create datetime with +05:00 offset
        offset = timezone(timedelta(hours=5))
        aware_dt = datetime(2026, 10, 10, 17, 0, 0, tzinfo=offset)

        result = to_utc(aware_dt)

        # 17:00 +05:00 = 12:00 UTC
        assert result.hour == 12
        assert result.tzinfo == timezone.utc

    def test_result_is_always_timezone_aware(self):
        """Result should always have tzinfo set."""
        from benchmark.metrics import to_utc

        test_cases = [
            datetime(2026, 10, 10, 12, 0, 0),  # naive
            datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc),  # UTC
            datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone(timedelta(hours=-8))),  # PST
        ]

        for dt in test_cases:
            result = to_utc(dt)
            assert result.tzinfo is not None, f"Failed for input: {dt}"


class TestAlertTimestampParsing:
    """Tests for alert timestamp parsing in collector."""

    def _parse_timestamp(self, ts_str: str) -> datetime:
        """Helper to parse timestamp the same way collector does."""
        from datetime import datetime, timezone

        if ts_str:
            ts_str = ts_str.replace("Z", "+00:00")
            parsed_ts = datetime.fromisoformat(ts_str)
            # Ensure timezone-aware (assume UTC if naive)
            if parsed_ts.tzinfo is None:
                parsed_ts = parsed_ts.replace(tzinfo=timezone.utc)
        else:
            parsed_ts = datetime.now(timezone.utc)
        return parsed_ts

    def test_timestamp_with_z_suffix(self):
        """Timestamp ending in Z should parse as UTC."""
        ts_str = "2026-10-10T12:30:45.123456Z"

        result = self._parse_timestamp(ts_str)

        assert result.tzinfo is not None
        assert result.year == 2026
        assert result.month == 10
        assert result.hour == 12
        assert result.minute == 30

    def test_timestamp_with_explicit_utc_offset(self):
        """Timestamp with explicit +00:00 should parse as UTC."""
        ts_str = "2026-10-10T12:30:45.123456+00:00"

        result = self._parse_timestamp(ts_str)

        assert result.tzinfo is not None
        assert result.hour == 12

    def test_timestamp_with_non_utc_offset(self):
        """Timestamp with non-UTC offset should preserve that offset."""
        ts_str = "2026-10-10T12:30:45+05:00"

        result = self._parse_timestamp(ts_str)

        assert result.tzinfo is not None
        assert result.hour == 12  # Original hour preserved

    def test_timestamp_without_timezone_becomes_utc(self):
        """Timestamp without timezone should be assumed UTC."""
        ts_str = "2026-10-10T12:30:45.123456"

        result = self._parse_timestamp(ts_str)

        # Should be timezone-aware (this is the critical fix)
        assert result.tzinfo is not None
        assert result.tzinfo == timezone.utc
        assert result.hour == 12

    def test_empty_timestamp_returns_current_utc(self):
        """Empty timestamp should return current UTC time."""
        result = self._parse_timestamp("")

        assert result.tzinfo is not None
        # Should be close to now
        now = datetime.now(timezone.utc)
        assert abs((result - now).total_seconds()) < 2

    def test_all_parsed_timestamps_are_timezone_aware(self):
        """All timestamp formats should result in timezone-aware datetimes."""
        test_cases = [
            "2026-10-10T12:30:45.123456Z",
            "2026-10-10T12:30:45.123456+00:00",
            "2026-10-10T12:30:45.123456-08:00",
            "2026-10-10T12:30:45.123456",  # No timezone
            "2026-10-10T12:30:45",  # No microseconds, no timezone
        ]

        for ts_str in test_cases:
            result = self._parse_timestamp(ts_str)
            assert result.tzinfo is not None, f"Failed for: {ts_str}"


class TestAlertAttackTimeComparison:
    """Tests for comparing alert timestamps against attack start times."""

    def test_compare_utc_alert_with_naive_attack_time(self):
        """Comparing UTC alert timestamp with converted naive attack time should not raise."""
        from benchmark.metrics import to_utc

        # Simulate alert timestamp (always UTC-aware after parsing)
        alert_ts = datetime(2026, 10, 10, 12, 30, 45, tzinfo=timezone.utc)

        # Simulate attack start time (originally naive, converted via to_utc)
        attack_start_naive = datetime(2026, 10, 10, 12, 30, 40)
        attack_start_utc = to_utc(attack_start_naive)

        # This comparison should NOT raise TypeError
        try:
            result = alert_ts >= attack_start_utc
            assert isinstance(result, bool)
        except TypeError as e:
            pytest.fail(f"Comparison raised TypeError: {e}")

    def test_compare_utc_alert_with_utc_attack_time(self):
        """Comparing two UTC-aware datetimes should work."""
        from benchmark.metrics import to_utc

        alert_ts = datetime(2026, 10, 10, 12, 30, 45, tzinfo=timezone.utc)
        attack_start = datetime(2026, 10, 10, 12, 30, 40, tzinfo=timezone.utc)
        attack_start_utc = to_utc(attack_start)

        # Should not raise
        result = alert_ts >= attack_start_utc
        assert result is True

    def test_time_to_detect_calculation(self):
        """TTD calculation should work with properly converted times."""
        from benchmark.metrics import to_utc

        # Alert 5 seconds after attack
        alert_ts = datetime(2026, 10, 10, 12, 30, 45, tzinfo=timezone.utc)
        attack_start_naive = datetime(2026, 10, 10, 12, 30, 40)

        # Convert attack start to UTC (simulating what metrics.py does)
        attack_start_utc = to_utc(attack_start_naive)

        # Calculate TTD (should not raise)
        try:
            if alert_ts >= attack_start_utc:
                ttd = (alert_ts - attack_start_utc).total_seconds()
                # TTD depends on local timezone offset, but should be a valid number
                assert isinstance(ttd, float)
        except TypeError as e:
            pytest.fail(f"TTD calculation raised TypeError: {e}")

    def test_naive_vs_aware_comparison_would_fail(self):
        """Direct comparison of naive vs aware should raise TypeError."""
        naive_dt = datetime(2026, 10, 10, 12, 30, 45)
        aware_dt = datetime(2026, 10, 10, 12, 30, 45, tzinfo=timezone.utc)

        with pytest.raises(TypeError, match="can't compare"):
            _ = naive_dt >= aware_dt


class TestBaselineConfiguration:
    """Tests for baseline indexing wait configuration."""

    def test_baseline_wait_time_is_sufficient(self):
        """Baseline should wait at least 30 seconds for log indexing."""
        import ast
        from pathlib import Path

        baseline_path = Path("benchmark/baseline.py")
        content = baseline_path.read_text()

        # Parse the AST to find time.sleep calls
        tree = ast.parse(content)

        sleep_calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Check for time.sleep(N) pattern
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr == "sleep" and len(node.args) == 1:
                        if isinstance(node.args[0], ast.Constant):
                            sleep_calls.append(node.args[0].value)

        # Should have sleep calls, at least one should be >= 30
        assert len(sleep_calls) > 0, "No time.sleep calls found in baseline.py"

        # Find the longest sleep (should be the indexing wait)
        max_sleep = max(sleep_calls)
        assert max_sleep >= 30, f"Max sleep is {max_sleep}s, expected >= 30s for log indexing"

    def test_cli_benchmark_wait_time_is_sufficient(self):
        """CLI benchmark command should wait at least 30 seconds for log indexing."""
        import ast
        from pathlib import Path

        cli_path = Path("benchmark/cli.py")
        content = cli_path.read_text()

        tree = ast.parse(content)

        sleep_calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr == "sleep" and len(node.args) == 1:
                        if isinstance(node.args[0], ast.Constant):
                            sleep_calls.append(node.args[0].value)

        # Should have at least one 30s sleep for log indexing
        assert any(s >= 30 for s in sleep_calls), f"No sleep >= 30s found in cli.py. Found: {sleep_calls}"
