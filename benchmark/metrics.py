"""Metrics calculation for detection benchmark results."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from benchmark.collector import AlertCollector, CollectionWindow
from benchmark.runner import AttackResult, BenchmarkRun


def to_utc(dt: datetime) -> datetime:
    """Convert a datetime to UTC. Assumes naive datetimes are local time."""
    if dt.tzinfo is None:
        return dt.astimezone().astimezone(timezone.utc)
    return dt.astimezone(timezone.utc)


@dataclass
class TechniqueMetrics:
    """Metrics for a single ATT&CK technique."""

    technique_id: str
    technique_name: str
    tactic: str
    tests_executed: int
    tests_detected: int
    detection_rate: float | None  # None = no test could be evaluated
    mean_time_to_detect_seconds: float | None
    alert_count: int
    false_negative_count: int
    collection_errors: int = 0  # tests whose Elasticsearch query failed
    attack_failures: int = 0  # tests whose attack command failed
    telemetry_missing: int = 0  # no match and no events from the expected log source

    @property
    def tests_evaluated(self) -> int:
        """Tests that support a conclusion about detection."""
        return (
            self.tests_executed
            - self.collection_errors
            - self.attack_failures
            - self.telemetry_missing
        )

    @property
    def status(self) -> str:
        """DETECTED, NOT DETECTED, or NOT EVALUATED."""
        if self.tests_detected > 0:
            return "DETECTED"
        if self.tests_evaluated > 0:
            return "NOT DETECTED"
        return "NOT EVALUATED"


@dataclass
class BenchmarkMetrics:
    """Aggregate metrics for a complete benchmark run."""

    run_id: str
    start_time: datetime
    end_time: datetime
    total_attacks: int
    total_detected: int
    overall_detection_rate: float | None  # None = no test could be evaluated
    mean_time_to_detect_seconds: float | None
    false_positive_rate_per_hour: float | None  # None = no baseline measured
    alert_volume_per_attack: float | None  # None = no test could be evaluated
    technique_metrics: list[TechniqueMetrics] = field(default_factory=list)
    detection_gaps: list[str] = field(default_factory=list)


class MetricsCalculator:
    """Calculates detection metrics from benchmark results."""

    # Default post-attack buffer in seconds
    DEFAULT_POST_BUFFER_SECONDS = 15

    # Log sources (Filebeat log_type) expected to carry evidence. A test with no
    # match is evaluated only if one of these produced events in its window.
    DEFAULT_LOG_TYPES = ["auditd"]
    TECHNIQUE_LOG_TYPES = {
        "T1136.001": ["auditd", "auth"],
        "T1053.003": ["auditd", "cron", "syslog"],
    }

    # Technique-specific post-attack buffers (seconds)
    # Cron requires 65s because cron daemon checks for changes at minute boundaries
    TECHNIQUE_POST_BUFFER = {
        "T1053.003": 65,  # Cron checks at :01 each minute; worst case ~60s delay
    }

    # Audit keys that indicate a detection for each technique
    TECHNIQUE_DETECTION_KEYS = {
        "T1059.004": ["exec", "EXECVE"],
        "T1053.003": ["cron_mod", "crontab"],
        "T1136.001": ["user_add", "user_mod", "useradd"],
        "T1548.001": ["priv_esc", "chmod", "setuid"],
        "T1070.004": ["file_delete", "unlink"],
        "T1070.003": ["shell_history", "bash_history", "HISTFILE"],
        "T1027": ["exec", "EXECVE", "base64"],
        "T1018": ["network_socket", "nmap"],
        "T1082": ["sys_info", "uname", "hostname"],
        "T1105": ["network_connect", "curl", "wget"],
        "T1571": ["network_connect", "netcat", "nc"],
    }

    def __init__(self, collector: AlertCollector):
        self.collector = collector

    def calculate_technique_metrics(
        self,
        technique_id: str,
        results: list[AttackResult],
    ) -> TechniqueMetrics:
        """Calculate metrics for a single technique."""
        if not results:
            return TechniqueMetrics(
                technique_id=technique_id,
                technique_name="Unknown",
                tactic="unknown",
                tests_executed=0,
                tests_detected=0,
                detection_rate=0.0,
                mean_time_to_detect_seconds=None,
                alert_count=0,
                false_negative_count=0,
            )

        first_result = results[0]
        tests_executed = len(results)
        tests_detected = 0
        collection_errors = 0
        attack_failures = 0
        telemetry_missing = 0
        total_alert_count = 0
        detection_times: list[float] = []

        detection_keys = self.TECHNIQUE_DETECTION_KEYS.get(technique_id, [])
        log_types = self.TECHNIQUE_LOG_TYPES.get(technique_id, self.DEFAULT_LOG_TYPES)

        for result in results:
            # An attack that did not run cannot be detected or missed
            if not result.success:
                attack_failures += 1
                continue

            # Define collection window around the attack
            # Use technique-specific buffer for delayed telemetry (e.g., cron)
            post_buffer = self.TECHNIQUE_POST_BUFFER.get(
                technique_id, self.DEFAULT_POST_BUFFER_SECONDS
            )
            window = CollectionWindow(
                start=result.start_time - timedelta(seconds=1),
                end=result.end_time + timedelta(seconds=post_buffer),
            )

            # Collect alerts for this attack
            alerts = self.collector.collect_alerts_for_technique(
                technique_id=technique_id,
                window=window,
                audit_keys=detection_keys,
            )

            # A failed query is neither a detection nor a miss
            if alerts is None:
                collection_errors += 1
                continue

            alert_count = len(alerts)
            total_alert_count += alert_count

            if alert_count > 0:
                tests_detected += 1

                # Calculate time to detect (first alert after attack start)
                attack_start_utc = to_utc(result.start_time)
                for alert in alerts:
                    if alert.timestamp >= attack_start_utc:
                        ttd = (alert.timestamp - attack_start_utc).total_seconds()
                        detection_times.append(ttd)
                        break
            else:
                # No match is a miss only if the expected log source was
                # producing events in this window
                telemetry = self.collector.count_logs_in_window(window, log_types=log_types)
                if telemetry is None:
                    collection_errors += 1
                elif telemetry == 0:
                    telemetry_missing += 1

        tests_evaluated = tests_executed - collection_errors - attack_failures - telemetry_missing
        detection_rate = tests_detected / tests_evaluated if tests_evaluated > 0 else None
        mean_ttd = (
            sum(detection_times) / len(detection_times) if detection_times else None
        )

        return TechniqueMetrics(
            technique_id=technique_id,
            technique_name=first_result.technique_name,
            tactic=first_result.tactic,
            tests_executed=tests_executed,
            tests_detected=tests_detected,
            detection_rate=detection_rate,
            mean_time_to_detect_seconds=mean_ttd,
            alert_count=total_alert_count,
            false_negative_count=tests_evaluated - tests_detected,
            collection_errors=collection_errors,
            attack_failures=attack_failures,
            telemetry_missing=telemetry_missing,
        )

    def calculate_benchmark_metrics(
        self,
        run: BenchmarkRun,
        baseline_window: CollectionWindow | None = None,
    ) -> BenchmarkMetrics:
        """Calculate aggregate metrics for a complete benchmark run."""
        # Group results by technique
        results_by_technique: dict[str, list[AttackResult]] = {}
        for result in run.attack_results:
            if result.technique_id not in results_by_technique:
                results_by_technique[result.technique_id] = []
            results_by_technique[result.technique_id].append(result)

        # Calculate per-technique metrics
        technique_metrics = []
        for technique_id, results in results_by_technique.items():
            metrics = self.calculate_technique_metrics(technique_id, results)
            technique_metrics.append(metrics)

        # Calculate aggregate metrics
        total_attacks = sum(m.tests_executed for m in technique_metrics)
        total_detected = sum(m.tests_detected for m in technique_metrics)
        total_evaluated = sum(m.tests_evaluated for m in technique_metrics)
        if total_evaluated > 0:
            overall_detection_rate = total_detected / total_evaluated
        else:
            # No attacks at all keeps the previous 0.0; all queries failed is unavailable
            overall_detection_rate = 0.0 if total_attacks == 0 else None

        # Calculate mean TTD across all techniques
        all_ttds = [
            m.mean_time_to_detect_seconds
            for m in technique_metrics
            if m.mean_time_to_detect_seconds is not None
        ]
        mean_ttd = sum(all_ttds) / len(all_ttds) if all_ttds else None

        # Calculate alert volume per attack
        total_alerts = sum(m.alert_count for m in technique_metrics)
        if total_evaluated > 0:
            alert_volume = total_alerts / total_evaluated
        else:
            alert_volume = 0.0 if total_attacks == 0 else None

        # Calculate FP rate if baseline window provided (None = not measured)
        fp_rate = None
        if baseline_window:
            # Count alerts during baseline that match detection patterns
            all_keywords = []
            for keys in self.TECHNIQUE_DETECTION_KEYS.values():
                all_keywords.extend(keys)
            fp_rate = self.collector.get_alert_rate(baseline_window, all_keywords)

        # Identify evaluated techniques with no detection (unevaluated ones have rate None)
        detection_gaps = [
            f"{m.technique_id} ({m.technique_name})"
            for m in technique_metrics
            if m.detection_rate == 0.0
        ]

        return BenchmarkMetrics(
            run_id=run.run_id,
            start_time=run.start_time,
            end_time=run.end_time or datetime.now(),
            total_attacks=total_attacks,
            total_detected=total_detected,
            overall_detection_rate=overall_detection_rate,
            mean_time_to_detect_seconds=mean_ttd,
            false_positive_rate_per_hour=fp_rate,
            alert_volume_per_attack=alert_volume,
            technique_metrics=technique_metrics,
            detection_gaps=detection_gaps,
        )


def calculate_metrics(
    run: BenchmarkRun,
    es_host: str = "localhost",
    es_port: int = 9200,
    baseline_window: CollectionWindow | None = None,
) -> BenchmarkMetrics:
    """Calculate metrics for a benchmark run."""
    collector = AlertCollector(es_host=es_host, es_port=es_port)
    calculator = MetricsCalculator(collector)
    return calculator.calculate_benchmark_metrics(run, baseline_window)
