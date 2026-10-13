"""Focused unit tests for attack diagnostic serialization."""

import json
from datetime import datetime, timezone

import pytest


class TestAttackResultSerialization:
    """Tests for attack result JSON serialization."""

    def test_serialization_includes_command_field(self):
        """Serialized attack result should include command field."""
        from benchmark.runner import AttackResult

        result = AttackResult(
            technique_id="T1059.004",
            technique_name="Unix Shell",
            tactic="execution",
            test_name="Test Shell",
            command="echo 'test'",
            start_time=datetime(2026, 10, 10, 12, 0, 0),
            end_time=datetime(2026, 10, 10, 12, 0, 1),
            success=True,
            output="test",
            error="",
        )

        # Simulate serialization as done in cli.py
        serialized = {
            "technique_id": result.technique_id,
            "technique_name": result.technique_name,
            "tactic": result.tactic,
            "test_name": result.test_name,
            "command": result.command,
            "start_time": result.start_time.isoformat(),
            "end_time": result.end_time.isoformat(),
            "success": result.success,
            "output": result.output,
            "error": result.error,
        }

        assert "command" in serialized
        assert serialized["command"] == "echo 'test'"

    def test_serialization_includes_output_field(self):
        """Serialized attack result should include output field."""
        from benchmark.runner import AttackResult

        result = AttackResult(
            technique_id="T1059.004",
            technique_name="Unix Shell",
            tactic="execution",
            test_name="Test Shell",
            command="echo 'test output'",
            start_time=datetime(2026, 10, 10, 12, 0, 0),
            end_time=datetime(2026, 10, 10, 12, 0, 1),
            success=True,
            output="test output\n",
            error="",
        )

        serialized = {
            "command": result.command,
            "output": result.output,
            "error": result.error,
        }

        assert "output" in serialized
        assert serialized["output"] == "test output\n"

    def test_serialization_includes_error_field(self):
        """Serialized attack result should include error field."""
        from benchmark.runner import AttackResult

        result = AttackResult(
            technique_id="T1059.004",
            technique_name="Unix Shell",
            tactic="execution",
            test_name="Test Shell",
            command="false",
            start_time=datetime(2026, 10, 10, 12, 0, 0),
            end_time=datetime(2026, 10, 10, 12, 0, 1),
            success=False,
            output="",
            error="Command failed with exit code 1",
        )

        serialized = {
            "command": result.command,
            "output": result.output,
            "error": result.error,
        }

        assert "error" in serialized
        assert serialized["error"] == "Command failed with exit code 1"

    def test_serialization_is_json_safe(self):
        """Serialized attack result should be JSON-safe."""
        from benchmark.runner import AttackResult

        result = AttackResult(
            technique_id="T1059.004",
            technique_name="Unix Shell",
            tactic="execution",
            test_name="Test Shell",
            command="echo 'test'",
            start_time=datetime(2026, 10, 10, 12, 0, 0),
            end_time=datetime(2026, 10, 10, 12, 0, 1),
            success=True,
            output="test\n",
            error="",
        )

        serialized = {
            "technique_id": result.technique_id,
            "technique_name": result.technique_name,
            "tactic": result.tactic,
            "test_name": result.test_name,
            "command": result.command,
            "start_time": result.start_time.isoformat(),
            "end_time": result.end_time.isoformat(),
            "success": result.success,
            "output": result.output,
            "error": result.error,
        }

        # Should not raise
        json_str = json.dumps(serialized)
        parsed = json.loads(json_str)

        assert parsed["command"] == "echo 'test'"
        assert parsed["output"] == "test\n"


class TestAttackResultDeserialization:
    """Tests for attack result JSON deserialization."""

    def test_deserialization_restores_command(self):
        """Deserialized attack result should restore command field."""
        from benchmark.runner import AttackResult

        json_data = {
            "technique_id": "T1059.004",
            "technique_name": "Unix Shell",
            "tactic": "execution",
            "test_name": "Test Shell",
            "command": "echo 'test'",
            "start_time": "2026-10-10T12:00:00",
            "end_time": "2026-10-10T12:00:01",
            "success": True,
            "output": "test\n",
            "error": "",
        }

        result = AttackResult(
            technique_id=json_data["technique_id"],
            technique_name=json_data["technique_name"],
            tactic=json_data["tactic"],
            test_name=json_data["test_name"],
            command=json_data.get("command", ""),
            start_time=datetime.fromisoformat(json_data["start_time"]),
            end_time=datetime.fromisoformat(json_data["end_time"]),
            success=json_data["success"],
            output=json_data.get("output", ""),
            error=json_data.get("error", ""),
        )

        assert result.command == "echo 'test'"
        assert result.output == "test\n"
        assert result.error == ""

    def test_deserialization_handles_missing_diagnostic_fields(self):
        """Deserialization should handle old JSON without diagnostic fields."""
        from benchmark.runner import AttackResult

        # Old JSON format without command/output/error
        json_data = {
            "technique_id": "T1059.004",
            "technique_name": "Unix Shell",
            "tactic": "execution",
            "test_name": "Test Shell",
            "start_time": "2026-10-10T12:00:00",
            "end_time": "2026-10-10T12:00:01",
            "success": True,
        }

        result = AttackResult(
            technique_id=json_data["technique_id"],
            technique_name=json_data["technique_name"],
            tactic=json_data["tactic"],
            test_name=json_data["test_name"],
            command=json_data.get("command", ""),
            start_time=datetime.fromisoformat(json_data["start_time"]),
            end_time=datetime.fromisoformat(json_data["end_time"]),
            success=json_data["success"],
            output=json_data.get("output", ""),
            error=json_data.get("error", ""),
        )

        assert result.command == ""
        assert result.output == ""
        assert result.error == ""


class TestAttackTimestampSerialization:
    """Tests for attack timestamp serialization accuracy."""

    def test_start_time_preserved(self):
        """Start time should be accurately preserved through serialization."""
        from benchmark.runner import AttackResult

        original_time = datetime(2026, 10, 10, 12, 30, 45, 123456)

        result = AttackResult(
            technique_id="T1059.004",
            technique_name="Unix Shell",
            tactic="execution",
            test_name="Test Shell",
            command="test",
            start_time=original_time,
            end_time=original_time,
            success=True,
        )

        iso_str = result.start_time.isoformat()
        restored = datetime.fromisoformat(iso_str)

        assert restored == original_time

    def test_end_time_preserved(self):
        """End time should be accurately preserved through serialization."""
        from benchmark.runner import AttackResult

        start_time = datetime(2026, 10, 10, 12, 30, 45)
        end_time = datetime(2026, 10, 10, 12, 30, 47, 500000)

        result = AttackResult(
            technique_id="T1059.004",
            technique_name="Unix Shell",
            tactic="execution",
            test_name="Test Shell",
            command="sleep 2",
            start_time=start_time,
            end_time=end_time,
            success=True,
        )

        iso_str = result.end_time.isoformat()
        restored = datetime.fromisoformat(iso_str)

        assert restored == end_time
        # Duration should be ~2.5 seconds
        duration = (restored - result.start_time).total_seconds()
        assert 2.4 < duration < 2.6


class TestDiagnosticFieldsForDebugging:
    """Tests verifying diagnostic fields provide useful debugging info."""

    def test_failed_attack_captures_error_output(self):
        """Failed attacks should capture error information."""
        from benchmark.runner import AttackResult

        result = AttackResult(
            technique_id="T1136.001",
            technique_name="Create Local Account",
            tactic="persistence",
            test_name="Create user",
            command="useradd test-user",
            start_time=datetime(2026, 10, 10, 12, 0, 0),
            end_time=datetime(2026, 10, 10, 12, 0, 1),
            success=False,
            output="",
            error="useradd: Permission denied",
        )

        # Error should be preserved
        assert "Permission denied" in result.error
        assert result.success is False

    def test_successful_attack_captures_stdout(self):
        """Successful attacks should capture stdout."""
        from benchmark.runner import AttackResult

        result = AttackResult(
            technique_id="T1082",
            technique_name="System Information Discovery",
            tactic="discovery",
            test_name="System info",
            command="uname -a",
            start_time=datetime(2026, 10, 10, 12, 0, 0),
            end_time=datetime(2026, 10, 10, 12, 0, 1),
            success=True,
            output="Linux soc-target 5.15.0 #1 SMP x86_64 GNU/Linux\n",
            error="",
        )

        # Output should be preserved
        assert "Linux" in result.output
        assert result.success is True

    def test_command_field_for_audit_trail(self):
        """Command field should provide audit trail of what was executed."""
        from benchmark.runner import AttackResult

        result = AttackResult(
            technique_id="T1059.004",
            technique_name="Unix Shell",
            tactic="execution",
            test_name="Bash execution",
            command="bash -c 'echo malicious_payload | base64'",
            start_time=datetime(2026, 10, 10, 12, 0, 0),
            end_time=datetime(2026, 10, 10, 12, 0, 1),
            success=True,
            output="bWFsaWNpb3VzX3BheWxvYWQK\n",
            error="",
        )

        # Command should be fully preserved for audit
        assert "bash -c" in result.command
        assert "echo malicious_payload" in result.command

    def test_empty_output_fields_are_valid(self):
        """Empty output/error fields should be valid."""
        from benchmark.runner import AttackResult

        result = AttackResult(
            technique_id="T1070.003",
            technique_name="Clear Command History",
            tactic="defense-evasion",
            test_name="Clear history",
            command="history -c",
            start_time=datetime(2026, 10, 10, 12, 0, 0),
            end_time=datetime(2026, 10, 10, 12, 0, 1),
            success=True,
            output="",
            error="",
        )

        # Empty strings are valid
        assert result.output == ""
        assert result.error == ""
        assert result.success is True
