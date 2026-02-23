"""Tests for WMI persistence scanning."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from aegis.detection.wmi_scanner import (
    WMIFinding,
    WMIPersistenceScanner,
)


class TestWMIFinding:
    """Unit tests for the WMIFinding dataclass."""

    def test_finding_creation(self) -> None:
        f = WMIFinding(
            namespace="root\\subscription",
            consumer_type="CommandLineEventConsumer",
            consumer_name="evil_backdoor",
            command_or_script="powershell -enc ...",
            risk="high",
            mitre_id="T1546.003",
        )
        assert f.consumer_type == "CommandLineEventConsumer"
        assert f.risk == "high"

    def test_finding_defaults(self) -> None:
        f = WMIFinding(
            namespace="root\\subscription",
            consumer_type="CommandLineEventConsumer",
            consumer_name="test",
            command_or_script="cmd.exe",
            risk="medium",
            mitre_id="T1546.003",
        )
        assert f.namespace == "root\\subscription"
        assert f.consumer_name == "test"
        assert f.command_or_script == "cmd.exe"
        assert f.mitre_id == "T1546.003"

    def test_finding_equality(self) -> None:
        kwargs = dict(
            namespace="root\\subscription",
            consumer_type="CommandLineEventConsumer",
            consumer_name="evil",
            command_or_script="cmd /c whoami",
            risk="high",
            mitre_id="T1546.003",
        )
        assert WMIFinding(**kwargs) == WMIFinding(**kwargs)


class TestScanNamespace:
    """Tests for _scan_namespace_with_conn low-level scanning."""

    def test_empty_namespace_no_findings(self) -> None:
        scanner = WMIPersistenceScanner()
        mock_wmi = MagicMock()
        mock_wmi.query.return_value = []

        findings = scanner._scan_namespace_with_conn(
            mock_wmi, "root\\subscription",
        )
        assert len(findings) == 0

    def test_command_line_consumer_high_risk(self) -> None:
        scanner = WMIPersistenceScanner()
        mock_wmi = MagicMock()

        mock_consumer = MagicMock()
        mock_consumer.Name = "evil_backdoor"
        mock_consumer.CommandLineTemplate = "powershell -enc ..."
        mock_consumer.wmi_class = "CommandLineEventConsumer"

        mock_wmi.query.side_effect = [
            [mock_consumer],  # CommandLineEventConsumer
            [],               # ActiveScriptEventConsumer
        ]

        findings = scanner._scan_namespace_with_conn(
            mock_wmi, "root\\subscription",
        )
        assert len(findings) >= 1
        assert findings[0].risk == "high"
        assert findings[0].consumer_name == "evil_backdoor"
        assert findings[0].consumer_type == "CommandLineEventConsumer"
        assert findings[0].command_or_script == "powershell -enc ..."
        assert findings[0].mitre_id == "T1546.003"

    def test_active_script_consumer_critical_risk(self) -> None:
        scanner = WMIPersistenceScanner()
        mock_wmi = MagicMock()

        mock_consumer = MagicMock()
        mock_consumer.Name = "vbs_backdoor"
        mock_consumer.ScriptText = 'CreateObject("WScript.Shell")...'
        mock_consumer.wmi_class = "ActiveScriptEventConsumer"

        mock_wmi.query.side_effect = [
            [],               # CommandLineEventConsumer
            [mock_consumer],  # ActiveScriptEventConsumer
        ]

        findings = scanner._scan_namespace_with_conn(
            mock_wmi, "root\\subscription",
        )
        assert len(findings) >= 1
        assert findings[0].risk == "critical"
        assert findings[0].consumer_name == "vbs_backdoor"
        assert findings[0].consumer_type == "ActiveScriptEventConsumer"
        assert findings[0].command_or_script == (
            'CreateObject("WScript.Shell")...'
        )

    def test_both_consumer_types_found(self) -> None:
        scanner = WMIPersistenceScanner()
        mock_wmi = MagicMock()

        mock_cmd = MagicMock()
        mock_cmd.Name = "cmd_consumer"
        mock_cmd.CommandLineTemplate = "cmd /c net user"
        mock_cmd.wmi_class = "CommandLineEventConsumer"

        mock_script = MagicMock()
        mock_script.Name = "script_consumer"
        mock_script.ScriptText = "Set ws = CreateObject(...)"
        mock_script.wmi_class = "ActiveScriptEventConsumer"

        mock_wmi.query.side_effect = [
            [mock_cmd],
            [mock_script],
        ]

        findings = scanner._scan_namespace_with_conn(
            mock_wmi, "root\\subscription",
        )
        assert len(findings) == 2
        risks = {f.risk for f in findings}
        assert "high" in risks
        assert "critical" in risks

    def test_query_exception_returns_empty(self) -> None:
        scanner = WMIPersistenceScanner()
        mock_wmi = MagicMock()
        mock_wmi.query.side_effect = Exception("WMI access denied")

        findings = scanner._scan_namespace_with_conn(
            mock_wmi, "root\\subscription",
        )
        assert len(findings) == 0


class TestScanNamespacePublic:
    """Tests for the public scan_namespace method."""

    def test_scan_namespace_import_error(self) -> None:
        scanner = WMIPersistenceScanner()
        with patch(
            "aegis.detection.wmi_scanner._connect_wmi",
            side_effect=ImportError("No module named 'wmi'"),
        ):
            findings = scanner.scan_namespace("root\\subscription")
            assert findings == []

    def test_scan_namespace_access_denied(self) -> None:
        scanner = WMIPersistenceScanner()
        with patch(
            "aegis.detection.wmi_scanner._connect_wmi",
            side_effect=PermissionError("Access denied"),
        ):
            findings = scanner.scan_namespace("root\\subscription")
            assert findings == []

    def test_scan_namespace_delegates(self) -> None:
        scanner = WMIPersistenceScanner()
        mock_conn = MagicMock()
        mock_conn.query.return_value = []
        with patch(
            "aegis.detection.wmi_scanner._connect_wmi",
            return_value=mock_conn,
        ):
            with patch.object(
                scanner, "_scan_namespace_with_conn",
                return_value=[],
            ) as mock_inner:
                scanner.scan_namespace("root\\subscription")
                mock_inner.assert_called_once_with(
                    mock_conn, "root\\subscription",
                )


class TestScanAll:
    """Tests for scan_all_namespaces."""

    def test_scan_all_calls_scan_namespace(self) -> None:
        scanner = WMIPersistenceScanner()
        with patch.object(
            scanner, "scan_namespace",
            return_value=[],
        ) as mock_scan:
            scanner.scan_all_namespaces()
            assert mock_scan.called

    def test_scan_all_includes_root_subscription(self) -> None:
        scanner = WMIPersistenceScanner()
        with patch.object(
            scanner, "scan_namespace",
            return_value=[],
        ) as mock_scan:
            scanner.scan_all_namespaces()
            namespaces_scanned = [
                call.args[0] for call in mock_scan.call_args_list
            ]
            assert "root\\subscription" in namespaces_scanned

    def test_scan_all_aggregates_findings(self) -> None:
        scanner = WMIPersistenceScanner()
        finding = WMIFinding(
            namespace="root\\subscription",
            consumer_type="CommandLineEventConsumer",
            consumer_name="evil",
            command_or_script="cmd /c whoami",
            risk="high",
            mitre_id="T1546.003",
        )
        with patch.object(
            scanner, "scan_namespace",
            return_value=[finding],
        ):
            results = scanner.scan_all_namespaces()
            assert len(results) >= 1
            assert results[0].consumer_name == "evil"


class TestEnumerateNamespaces:
    """Tests for _enumerate_namespaces."""

    def test_enumerate_returns_list(self) -> None:
        scanner = WMIPersistenceScanner()
        with patch(
            "aegis.detection.wmi_scanner._connect_wmi",
        ) as mock_conn_fn:
            mock_conn = MagicMock()
            ns1 = MagicMock()
            ns1.Name = "subscription"
            mock_conn.query.return_value = [ns1]
            mock_conn_fn.return_value = mock_conn

            namespaces = scanner._enumerate_namespaces("root")
            assert "root\\subscription" in namespaces

    def test_enumerate_failure_returns_empty(self) -> None:
        scanner = WMIPersistenceScanner()
        with patch(
            "aegis.detection.wmi_scanner._connect_wmi",
            side_effect=Exception("Cannot connect"),
        ):
            namespaces = scanner._enumerate_namespaces("root")
            assert namespaces == []
