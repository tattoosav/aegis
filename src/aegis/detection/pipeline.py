"""Detection Pipeline — orchestrates all detection engines.

Implements the cascade + parallel detection flow from the design document:

1. Rule Engine (fast path — known threat signatures)
2. Isolation Forest → Autoencoder cascade (statistical → deep anomaly)
3. Parallel engines: LSTM, URL Classifier, Graph Analyzer

The pipeline is **detection only** — it produces Alert objects that are
presented to the user in the UI.  No response action is ever triggered
automatically; the user must explicitly approve every action.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from aegis.core.models import (
    AegisEvent,
    Alert,
    AlertStatus,
    Severity,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Threshold constants (from design doc Section 4.7)
# ---------------------------------------------------------------------------

IF_SUSPICIOUS_THRESHOLD = 0.4
IF_ANOMALOUS_THRESHOLD = 0.6


# ---------------------------------------------------------------------------
# DetectionPipeline
# ---------------------------------------------------------------------------

class DetectionPipeline:
    """Orchestrate detection engines and produce :class:`Alert` objects.

    The pipeline never triggers response actions.  All alerts are
    routed to the UI where the user decides how to respond.

    Parameters
    ----------
    rule_engine:
        Instance with ``evaluate(event) -> list[matched_rules]``.
    anomaly_detector:
        Instance with ``score(features) -> float``,
        ``classify(score) -> str``, ``extract_features(event)``.
    autoencoder:
        Instance with ``verify(features) -> (bool, float)``.
    lstm_analyzer:
        Instance with ``detect_beaconing(events) -> dict | None``.
    url_classifier:
        Instance with ``predict(url) -> dict``.
    graph_analyzer:
        Instance with ``add_event(event)``, ``analyze() -> list[ChainMatch]``.
    """

    def __init__(
        self,
        rule_engine: Any = None,
        anomaly_detector: Any = None,
        autoencoder: Any = None,
        lstm_analyzer: Any = None,
        url_classifier: Any = None,
        graph_analyzer: Any = None,
    ) -> None:
        self._rule_engine = rule_engine
        self._anomaly_detector = anomaly_detector
        self._autoencoder = autoencoder
        self._lstm_analyzer = lstm_analyzer
        self._url_classifier = url_classifier
        self._graph_analyzer = graph_analyzer

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process_event(self, event: AegisEvent) -> list[Alert]:
        """Run *event* through all detection engines.

        Returns a list of :class:`Alert` objects (may be empty).
        """
        alerts: list[Alert] = []

        # 1. Rule engine — fast path for known signatures
        rule_alert = self._run_rule_engine(event)
        if rule_alert is not None:
            alerts.append(rule_alert)

        # 2. Statistical cascade (Isolation Forest → Autoencoder)
        cascade_alert = self._run_statistical_cascade(event)
        if cascade_alert is not None:
            alerts.append(cascade_alert)

        # 3. Parallel / independent engines
        alerts.extend(self._run_parallel_engines(event))

        return alerts

    # ------------------------------------------------------------------
    # Rule engine
    # ------------------------------------------------------------------

    def _run_rule_engine(self, event: AegisEvent) -> Alert | None:
        """Check *event* against behavioural rules."""
        if self._rule_engine is None:
            return None
        try:
            matches = self._rule_engine.evaluate(event)
            if not matches:
                return None
            top = matches[0]
            return self._make_alert(
                event=event,
                alert_type=f"rule_{top.name}",
                title=top.description,
                severity=Severity.from_string(top.severity),
                confidence=0.95,
                mitre_ids=[top.mitre] if hasattr(top, "mitre") and top.mitre else [],
                engine="rule_engine",
            )
        except Exception:
            logger.exception("Rule engine failed for event %s", event.event_id)
            return None

    # ------------------------------------------------------------------
    # Statistical cascade
    # ------------------------------------------------------------------

    def _run_statistical_cascade(self, event: AegisEvent) -> Alert | None:
        """Isolation Forest → Autoencoder verification cascade."""
        if self._anomaly_detector is None:
            return None
        try:
            features = self._anomaly_detector.extract_features(event)
            if features is None:
                return None
            score = self._anomaly_detector.score(features)
            classification = self._anomaly_detector.classify(score)

            if classification == "normal":
                return None

            if classification == "suspicious":
                return self._make_alert(
                    event=event,
                    alert_type="statistical_anomaly",
                    title="Suspicious activity detected",
                    severity=Severity.MEDIUM,
                    confidence=round(score, 3),
                    engine="isolation_forest",
                )

            # classification == "anomalous" → verify with autoencoder
            if self._autoencoder is not None:
                try:
                    is_anomaly, recon_error = self._autoencoder.verify(features)
                    if not is_anomaly:
                        logger.debug(
                            "Autoencoder suppressed false positive for %s "
                            "(recon_error=%.4f)",
                            event.event_id,
                            recon_error,
                        )
                        return None
                    return self._make_alert(
                        event=event,
                        alert_type="confirmed_anomaly",
                        title="Confirmed anomaly detected",
                        severity=Severity.HIGH,
                        confidence=round(min(score + 0.1, 1.0), 3),
                        engine="autoencoder",
                    )
                except Exception:
                    logger.exception(
                        "Autoencoder failed; falling back to IF score"
                    )

            # Autoencoder unavailable or failed — use IF score directly
            return self._make_alert(
                event=event,
                alert_type="statistical_anomaly",
                title="Anomalous activity detected",
                severity=Severity.HIGH,
                confidence=round(score, 3),
                engine="isolation_forest",
            )
        except Exception:
            logger.exception(
                "Statistical cascade failed for event %s", event.event_id
            )
            return None

    # ------------------------------------------------------------------
    # Parallel / independent engines
    # ------------------------------------------------------------------

    def _run_parallel_engines(self, event: AegisEvent) -> list[Alert]:
        """Run LSTM, URL Classifier, and Graph Analyzer."""
        alerts: list[Alert] = []

        # URL Classifier — only for events with URL data
        url = event.data.get("url") or event.data.get("domain")
        if url and self._url_classifier is not None:
            alert = self._run_url_classifier(event, url)
            if alert is not None:
                alerts.append(alert)

        # Graph Analyzer — feed event and check for chain matches
        if self._graph_analyzer is not None:
            alerts.extend(self._run_graph_analyzer(event))

        # LSTM — detect temporal patterns (beaconing, brute force)
        if self._lstm_analyzer is not None:
            alert = self._run_lstm_analyzer(event)
            if alert is not None:
                alerts.append(alert)

        return alerts

    def _run_url_classifier(
        self, event: AegisEvent, url: str,
    ) -> Alert | None:
        """Classify a URL from the event."""
        try:
            result = self._url_classifier.predict(url)
            label = result.get("label", "benign")
            if label == "benign":
                return None
            confidence = result.get("confidence", 0.7)
            severity = Severity.HIGH if label == "malicious" else Severity.MEDIUM
            return self._make_alert(
                event=event,
                alert_type=f"url_{label}",
                title=f"{label.title()} URL detected: {url[:80]}",
                severity=severity,
                confidence=round(confidence, 3),
                engine="url_classifier",
            )
        except Exception:
            logger.exception("URL classifier failed for %s", url[:80])
            return None

    def _run_graph_analyzer(self, event: AegisEvent) -> list[Alert]:
        """Feed event to the context graph and check for attack chains."""
        alerts: list[Alert] = []
        try:
            self._graph_analyzer.add_event(event)
            chain_matches = self._graph_analyzer.analyze()
            for match in chain_matches:
                alerts.append(self._make_alert(
                    event=event,
                    alert_type=f"chain_{match.chain_name}",
                    title=f"Attack chain detected: {match.chain_name}",
                    severity=Severity.CRITICAL,
                    confidence=round(match.confidence, 3),
                    mitre_ids=list(match.mitre_ids),
                    engine="graph_analyzer",
                ))
        except Exception:
            logger.exception("Graph analyzer failed for event %s", event.event_id)
        return alerts

    def _run_lstm_analyzer(self, event: AegisEvent) -> Alert | None:
        """Check for temporal patterns (beaconing, brute force)."""
        try:
            result = self._lstm_analyzer.detect_beaconing([event])
            if result is None:
                return None
            return self._make_alert(
                event=event,
                alert_type="temporal_pattern",
                title=result.get("description", "Temporal pattern detected"),
                severity=Severity.HIGH,
                confidence=result.get("confidence", 0.75),
                engine="lstm_analyzer",
            )
        except Exception:
            logger.exception("LSTM analyzer failed for event %s", event.event_id)
            return None

    # ------------------------------------------------------------------
    # Alert factory
    # ------------------------------------------------------------------

    @staticmethod
    def _make_alert(
        event: AegisEvent,
        alert_type: str,
        title: str,
        severity: Severity,
        confidence: float,
        engine: str,
        mitre_ids: list[str] | None = None,
    ) -> Alert:
        """Create an :class:`Alert` from detection results."""
        return Alert(
            event_id=event.event_id,
            sensor=event.sensor,
            alert_type=alert_type,
            severity=severity,
            title=title,
            description=f"Detected by {engine} at {event.timestamp:.0f}",
            confidence=confidence,
            data={**event.data, "_engine": engine},
            status=AlertStatus.NEW,
            timestamp=time.time(),
            alert_id=f"alt-{uuid.uuid4().hex[:12]}",
            mitre_ids=mitre_ids or [],
        )
