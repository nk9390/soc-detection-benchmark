"""Alert collector for harvesting detection events from Elasticsearch."""

import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any


def to_utc_iso(dt: datetime) -> str:
    """Convert a datetime to UTC ISO format for Elasticsearch queries.

    Assumes naive datetimes are in local time and converts to UTC.
    """
    if dt.tzinfo is None:
        # Naive datetime - assume local time, convert to UTC
        local_dt = dt.astimezone()  # Add local timezone
        utc_dt = local_dt.astimezone(timezone.utc)
    else:
        utc_dt = dt.astimezone(timezone.utc)
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

from elasticsearch import Elasticsearch
from rich.console import Console

console = Console()


@dataclass
class Alert:
    """A detection alert from Elasticsearch."""

    timestamp: datetime
    rule_id: str | None
    rule_name: str | None
    log_type: str
    technique_id: str | None
    message: str
    raw: dict[str, Any]


@dataclass
class CollectionWindow:
    """Time window for alert collection."""

    start: datetime
    end: datetime


class AlertCollector:
    """Collects alerts from Elasticsearch."""

    def __init__(
        self,
        es_host: str = "localhost",
        es_port: int = 9200,
        index_pattern: str = "soc-benchmark-*",
    ):
        self.es = Elasticsearch(
            [f"http://{es_host}:{es_port}"],
            request_timeout=30,
        )
        self.index_pattern = index_pattern

    def wait_for_elasticsearch(self, timeout: int = 60) -> bool:
        """Wait for Elasticsearch to be available."""
        start = time.time()
        while time.time() - start < timeout:
            try:
                if self.es.ping():
                    return True
            except Exception:
                pass
            time.sleep(1)
        return False

    def collect_logs(
        self,
        window: CollectionWindow,
        log_types: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Collect raw logs within a time window."""
        query = {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": to_utc_iso(window.start),
                                "lte": to_utc_iso(window.end),
                            }
                        }
                    }
                ]
            }
        }

        if log_types:
            query["bool"]["filter"] = [{"terms": {"log_type": log_types}}]

        try:
            response = self.es.search(
                index=self.index_pattern,
                query=query,
                size=10000,
                sort=[{"@timestamp": "asc"}],
            )

            return [hit["_source"] for hit in response["hits"]["hits"]]

        except Exception as e:
            console.print(f"[red]Error collecting logs: {e}[/red]")
            return []

    def collect_alerts_for_technique(
        self,
        technique_id: str,
        window: CollectionWindow,
        audit_keys: list[str] | None = None,
    ) -> list[Alert]:
        """Collect alerts that match a specific technique."""
        alerts = []

        # Build query for matching audit events
        must_clauses = [
            {
                "range": {
                    "@timestamp": {
                        "gte": to_utc_iso(window.start),
                        "lte": to_utc_iso(window.end),
                    }
                }
            }
        ]

        if audit_keys:
            # Match on audit key field
            should_clauses = [{"match": {"message": key}} for key in audit_keys]
            must_clauses.append({"bool": {"should": should_clauses, "minimum_should_match": 1}})

        query = {"bool": {"must": must_clauses}}

        try:
            response = self.es.search(
                index=self.index_pattern,
                query=query,
                size=1000,
                sort=[{"@timestamp": "asc"}],
            )

            for hit in response["hits"]["hits"]:
                source = hit["_source"]
                # Parse timestamp and ensure it's timezone-aware (UTC)
                ts_str = source.get("@timestamp", "")
                if ts_str:
                    ts_str = ts_str.replace("Z", "+00:00")
                    parsed_ts = datetime.fromisoformat(ts_str)
                    # Ensure timezone-aware (assume UTC if naive)
                    if parsed_ts.tzinfo is None:
                        parsed_ts = parsed_ts.replace(tzinfo=timezone.utc)
                else:
                    parsed_ts = datetime.now(timezone.utc)

                alert = Alert(
                    timestamp=parsed_ts,
                    rule_id=None,
                    rule_name=None,
                    log_type=source.get("log_type", "unknown"),
                    technique_id=technique_id,
                    message=source.get("message", ""),
                    raw=source,
                )
                alerts.append(alert)

        except Exception as e:
            console.print(f"[red]Error collecting alerts: {e}[/red]")

        return alerts

    def count_logs_in_window(self, window: CollectionWindow) -> int:
        """Count total logs in a time window."""
        query = {
            "range": {
                "@timestamp": {
                    "gte": to_utc_iso(window.start),
                    "lte": to_utc_iso(window.end),
                }
            }
        }

        try:
            response = self.es.count(index=self.index_pattern, query=query)
            return response["count"]
        except Exception:
            return 0

    def get_alert_rate(self, window: CollectionWindow, keywords: list[str]) -> float:
        """Calculate alert rate (alerts per hour) for specific keywords."""
        duration_hours = (window.end - window.start).total_seconds() / 3600

        if duration_hours == 0:
            return 0.0

        should_clauses = [{"match": {"message": kw}} for kw in keywords]

        query = {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": to_utc_iso(window.start),
                                "lte": to_utc_iso(window.end),
                            }
                        }
                    },
                    {"bool": {"should": should_clauses, "minimum_should_match": 1}},
                ]
            }
        }

        try:
            response = self.es.count(index=self.index_pattern, query=query)
            return response["count"] / duration_hours
        except Exception:
            return 0.0


def collect_for_run(
    start_time: datetime,
    end_time: datetime,
    es_host: str = "localhost",
    es_port: int = 9200,
) -> list[dict[str, Any]]:
    """Collect all logs for a benchmark run."""
    collector = AlertCollector(es_host=es_host, es_port=es_port)

    window = CollectionWindow(
        start=start_time - timedelta(seconds=5),
        end=end_time + timedelta(seconds=10),
    )

    return collector.collect_logs(window)


if __name__ == "__main__":
    collector = AlertCollector()

    if collector.wait_for_elasticsearch():
        console.print("[green]Elasticsearch is available[/green]")

        window = CollectionWindow(
            start=datetime.now() - timedelta(hours=1),
            end=datetime.now(),
        )

        count = collector.count_logs_in_window(window)
        console.print(f"Logs in last hour: {count}")
    else:
        console.print("[red]Elasticsearch is not available[/red]")
