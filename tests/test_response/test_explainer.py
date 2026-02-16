"""Tests for NarrativeGenerator and ThreatExplainer."""

from __future__ import annotations

import time

import pytest

from aegis.core.models import (
    Alert,
    AlertStatus,
    SensorType,
    Severity,
)
from aegis.detection.graph_analyzer import ChainMatch
from aegis.detection.narratives import NarrativeGenerator
from aegis.response.explainer import ThreatExplainer

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

_CHAIN_NAMES: list[str] = [
    "drive_by_download",
    "credential_theft",
    "ransomware",
    "persistence_installation",
    "fileless_attack",
    "lateral_movement",
    "data_exfiltration",
    "dll_injection",
]


def _make_chain_match(
    chain_name: str = "ransomware",
    confidence: float = 0.9,
    mitre_ids: list[str] | None = None,
    matched_nodes: list[str] | None = None,
    description: str = "Test description.",
    severity: str = "CRITICAL",
) -> ChainMatch:
    return ChainMatch(
        chain_name=chain_name,
        confidence=confidence,
        mitre_ids=mitre_ids if mitre_ids is not None else ["T1486"],
        matched_nodes=matched_nodes if matched_nodes is not None else ["n1", "n2", "n3"],
        description=description,
        severity=severity,
        timestamp=time.time(),
    )


def _make_alert(
    sensor: SensorType = SensorType.NETWORK,
    severity: Severity = Severity.HIGH,
    alert_type: str = "anomaly",
    title: str = "Suspicious outbound connection",
    description: str = "Connection to known C2 IP detected.",
    confidence: float = 0.85,
    mitre_ids: list[str] | None = None,
    recommended_actions: list[str] | None = None,
) -> Alert:
    return Alert(
        event_id="evt-test123",
        sensor=sensor,
        alert_type=alert_type,
        severity=severity,
        title=title,
        description=description,
        confidence=confidence,
        data={"dst_ip": "45.33.32.1"},
        status=AlertStatus.NEW,
        mitre_ids=mitre_ids if mitre_ids is not None else ["T1071"],
        recommended_actions=recommended_actions if recommended_actions is not None else [
            "Block the IP at the firewall.",
            "Investigate the originating process.",
        ],
    )


# ===========================================================================
# NarrativeGenerator tests
# ===========================================================================

class TestNarrativeGeneratorGenerate:
    """Test NarrativeGenerator.generate() for each chain type."""

    @pytest.mark.parametrize("chain_name", _CHAIN_NAMES)
    def test_generate_returns_nonempty_string(
        self, chain_name: str,
    ) -> None:
        gen = NarrativeGenerator()
        match = _make_chain_match(chain_name=chain_name)
        narrative = gen.generate(match)
        assert isinstance(narrative, str)
        assert len(narrative) > 0

    @pytest.mark.parametrize("chain_name", _CHAIN_NAMES)
    def test_narrative_includes_severity(
        self, chain_name: str,
    ) -> None:
        gen = NarrativeGenerator()
        match = _make_chain_match(chain_name=chain_name, severity="HIGH")
        narrative = gen.generate(match)
        assert "HIGH" in narrative

    @pytest.mark.parametrize("chain_name", _CHAIN_NAMES)
    def test_narrative_includes_mitre_ids(
        self, chain_name: str,
    ) -> None:
        gen = NarrativeGenerator()
        match = _make_chain_match(
            chain_name=chain_name,
            mitre_ids=["T1059.001", "T1027"],
        )
        narrative = gen.generate(match)
        assert "T1059.001" in narrative
        assert "T1027" in narrative

    @pytest.mark.parametrize("chain_name", _CHAIN_NAMES)
    def test_narrative_includes_recommended_actions(
        self, chain_name: str,
    ) -> None:
        gen = NarrativeGenerator()
        match = _make_chain_match(chain_name=chain_name)
        narrative = gen.generate(match)
        assert "Recommended actions:" in narrative
        assert "  - " in narrative

    def test_narrative_includes_confidence_pct(self) -> None:
        gen = NarrativeGenerator()
        match = _make_chain_match(confidence=0.85)
        narrative = gen.generate(match)
        assert "85.0%" in narrative

    def test_narrative_includes_description(self) -> None:
        gen = NarrativeGenerator()
        match = _make_chain_match(description="Files were encrypted.")
        narrative = gen.generate(match)
        assert "Files were encrypted." in narrative

    def test_narrative_includes_node_count(self) -> None:
        gen = NarrativeGenerator()
        match = _make_chain_match(
            matched_nodes=["a", "b", "c", "d", "e"],
        )
        narrative = gen.generate(match)
        assert "5" in narrative

    def test_unknown_chain_uses_fallback(self) -> None:
        gen = NarrativeGenerator()
        match = _make_chain_match(chain_name="unknown_chain_xyz")
        narrative = gen.generate(match)
        assert "unknown_chain_xyz" in narrative
        assert "ATTACK DETECTED" in narrative

    def test_unknown_chain_has_generic_actions(self) -> None:
        gen = NarrativeGenerator()
        match = _make_chain_match(chain_name="unknown_chain_xyz")
        narrative = gen.generate(match)
        assert "Investigate" in narrative

    def test_empty_mitre_ids_shows_na(self) -> None:
        gen = NarrativeGenerator()
        match = _make_chain_match(mitre_ids=[])
        narrative = gen.generate(match)
        assert "N/A" in narrative


class TestNarrativeGeneratorActions:
    """Test _get_recommended_actions."""

    @pytest.mark.parametrize("chain_name", _CHAIN_NAMES)
    def test_returns_list_of_strings(self, chain_name: str) -> None:
        actions = NarrativeGenerator._get_recommended_actions(chain_name)
        assert isinstance(actions, list)
        assert len(actions) >= 3
        assert all(isinstance(a, str) for a in actions)

    def test_unknown_chain_returns_generic_actions(self) -> None:
        actions = NarrativeGenerator._get_recommended_actions("nope")
        assert len(actions) >= 3
        assert any("Investigate" in a for a in actions)


# ===========================================================================
# ThreatExplainer.explain_alert tests
# ===========================================================================

class TestExplainAlert:
    """Test ThreatExplainer.explain_alert() across sensor/severity combos."""

    def test_network_high_uses_sensor_severity_template(self) -> None:
        explainer = ThreatExplainer()
        alert = _make_alert(
            sensor=SensorType.NETWORK, severity=Severity.HIGH,
        )
        result = explainer.explain_alert(alert)
        assert "HIGH-SEVERITY NETWORK ALERT" in result
        assert alert.title in result

    def test_process_critical_template(self) -> None:
        explainer = ThreatExplainer()
        alert = _make_alert(
            sensor=SensorType.PROCESS, severity=Severity.CRITICAL,
        )
        result = explainer.explain_alert(alert)
        assert "CRITICAL PROCESS THREAT" in result

    def test_network_info_template(self) -> None:
        explainer = ThreatExplainer()
        alert = _make_alert(
            sensor=SensorType.NETWORK, severity=Severity.INFO,
        )
        result = explainer.explain_alert(alert)
        assert "Network info" in result
        assert "No immediate action required" in result

    def test_alert_type_overrides_sensor_severity(self) -> None:
        explainer = ThreatExplainer()
        alert = _make_alert(
            sensor=SensorType.NETWORK,
            severity=Severity.HIGH,
            alert_type="dns_tunneling",
        )
        result = explainer.explain_alert(alert)
        assert "DNS Tunneling" in result

    def test_port_scan_alert_type(self) -> None:
        explainer = ThreatExplainer()
        alert = _make_alert(alert_type="port_scan")
        result = explainer.explain_alert(alert)
        assert "Port Scan" in result

    def test_brute_force_alert_type(self) -> None:
        explainer = ThreatExplainer()
        alert = _make_alert(alert_type="brute_force")
        result = explainer.explain_alert(alert)
        assert "Brute-Force" in result

    def test_fallback_for_unknown_sensor_severity(self) -> None:
        explainer = ThreatExplainer()
        alert = _make_alert(
            sensor=SensorType.CLIPBOARD,
            severity=Severity.LOW,
            alert_type="unknown_type_xyz",
        )
        result = explainer.explain_alert(alert)
        assert "Security Alert" in result
        assert alert.title in result

    def test_explanation_includes_confidence(self) -> None:
        explainer = ThreatExplainer()
        alert = _make_alert(confidence=0.72)
        result = explainer.explain_alert(alert)
        assert "72.0%" in result

    def test_explanation_includes_description(self) -> None:
        explainer = ThreatExplainer()
        alert = _make_alert(description="Custom desc here.")
        result = explainer.explain_alert(alert)
        assert "Custom desc here." in result

    def test_explanation_includes_actions(self) -> None:
        explainer = ThreatExplainer()
        alert = _make_alert(
            recommended_actions=["Do step one.", "Do step two."],
        )
        result = explainer.explain_alert(alert)
        assert "Do step one." in result
        assert "Do step two." in result

    def test_empty_actions_shows_default(self) -> None:
        explainer = ThreatExplainer()
        alert = _make_alert(recommended_actions=[])
        result = explainer.explain_alert(alert)
        assert "Review the alert" in result


# ===========================================================================
# ThreatExplainer.explain_chain tests
# ===========================================================================

class TestExplainChain:
    """Test ThreatExplainer.explain_chain() delegation."""

    def test_delegates_to_narrative_generator(self) -> None:
        explainer = ThreatExplainer()
        match = _make_chain_match(chain_name="ransomware")
        result = explainer.explain_chain(match)
        assert "ATTACK DETECTED" in result
        assert "Ransomware" in result

    def test_chain_explanation_matches_direct_generation(self) -> None:
        explainer = ThreatExplainer()
        gen = NarrativeGenerator()
        match = _make_chain_match(chain_name="dll_injection")
        assert explainer.explain_chain(match) == gen.generate(match)
