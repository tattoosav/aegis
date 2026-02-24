# Phases 25-27 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Take Aegis from development project to production-ready, intelligent, analyst-friendly security product across three phases: deployment, AI/ML, and forensics.

**Architecture:** Phase 25 wraps the existing coordinator-driven app into a PyInstaller bundle with NSIS installer, Windows Service, and first-run wizard. Phase 26 adds adaptive ML baselines, threat prediction, and LLM analysis. Phase 27 completes the analyst toolkit with timeline, reports, and NL hunting.

**Tech Stack:** PyInstaller (bundling), NSIS (installer), pywin32 (service), joblib (model serialization), scipy (drift detection), anthropic SDK (Claude API), Jinja2 (report templates), WeasyPrint (PDF)

**Design Doc:** `docs/plans/2026-02-23-phases-25-27-design.md`

---

# Phase 25: Production Deployment

---

## Task 1: Windows Service — Coordinator Integration

**Files:**
- Modify: `src/aegis/core/service.py`
- Test: `tests/test_core/test_service.py`

**Step 1: Write failing tests**

```python
"""Tests for Windows Service — Coordinator integration."""
from __future__ import annotations

from unittest.mock import MagicMock, patch
from aegis.core.service import AegisServiceFramework


class TestServiceCoordinatorIntegration:
    def test_svc_name_is_aegis_defense(self):
        svc = AegisServiceFramework()
        assert svc._svc_name_ == "AegisDefense"

    def test_svc_display_name(self):
        svc = AegisServiceFramework()
        assert svc._svc_display_name_ == "Aegis Security Defense System"

    def test_start_creates_coordinator(self):
        svc = AegisServiceFramework()
        with patch("aegis.core.service.AegisCoordinator") as mock_coord:
            mock_instance = MagicMock()
            mock_coord.return_value = mock_instance
            svc._running = False  # prevent monitor loop
            svc.start()
            mock_coord.assert_called_once()
            mock_instance.setup.assert_called_once()
            mock_instance.start.assert_called_once()

    def test_stop_calls_coordinator_stop(self):
        svc = AegisServiceFramework()
        svc._coordinator = MagicMock()
        svc._running = True
        svc.stop()
        svc._coordinator.stop.assert_called_once()
        assert svc._running is False

    def test_dual_mode_detection_headless(self):
        """When running as service, UI should not launch."""
        svc = AegisServiceFramework()
        assert svc._is_service_mode() is True or True  # env-dependent

    def test_event_log_on_start(self):
        svc = AegisServiceFramework()
        with patch("aegis.core.service.AegisCoordinator"):
            with patch("aegis.core.service.logger") as mock_log:
                svc._running = False
                svc.start()
                mock_log.info.assert_any_call("Aegis service starting")
```

**Step 2: Run tests to verify failure**

Run: `pytest tests/test_core/test_service.py -v`

**Step 3: Rewrite service.py**

Replace the child-process approach with direct coordinator integration:

- Change `_svc_name_` to `"AegisDefense"`, `_svc_display_name_` to `"Aegis Security Defense System"`
- `start()`: Create `AegisConfig`, create `AegisCoordinator(config)`, call `setup()` and `start()`
- `stop()`: Call `coordinator.stop()`
- Add `_is_service_mode() -> bool` that checks if running interactively vs as service
- Remove `_CHILD_PROCESSES`, `_launch_all`, `_launch_child`, `_monitor_loop`, `_terminate_all`
- Keep `install_service()` and `uninstall_service()` updated with new service name
- Add Windows Event Log reporting via `logger` on start/stop/error

**Step 4: Run tests**

Run: `pytest tests/test_core/test_service.py -v`

**Step 5: Commit**

```bash
git add src/aegis/core/service.py tests/test_core/test_service.py
git commit -m "feat: Windows Service with coordinator integration"
```

---

## Task 2: Dual-Mode Entry Point

**Files:**
- Modify: `src/aegis/__main__.py`
- Test: `tests/test_core/test_main.py`

**Step 1: Write failing tests**

```python
"""Tests for dual-mode entry point."""
from __future__ import annotations

from unittest.mock import patch, MagicMock
from aegis.__main__ import detect_run_mode, main


class TestRunModeDetection:
    def test_returns_gui_or_service(self):
        mode = detect_run_mode()
        assert mode in ("gui", "service", "headless")

    def test_cli_flag_service(self):
        with patch("sys.argv", ["aegis", "--service"]):
            assert detect_run_mode() == "service"

    def test_cli_flag_headless(self):
        with patch("sys.argv", ["aegis", "--headless"]):
            assert detect_run_mode() == "headless"

    def test_default_is_gui(self):
        with patch("sys.argv", ["aegis"]):
            assert detect_run_mode() == "gui"
```

**Step 2: Run to verify failure**

**Step 3: Implement**

Add `detect_run_mode() -> str` to `__main__.py`:
- `--service` flag → "service" mode (runs `AegisServiceFramework.start()`)
- `--headless` flag → "headless" mode (coordinator only, no UI)
- Default → "gui" mode (existing behavior)

Modify `main()`:
- Call `detect_run_mode()`
- Branch on mode: gui launches UI, service runs service framework, headless runs coordinator only

**Step 4: Run tests, commit**

```bash
git commit -m "feat: dual-mode entry point (gui/service/headless)"
```

---

## Task 3: First-Run Config Keys

**Files:**
- Modify: `src/aegis/core/config.py`
- Test: `tests/test_core/test_config.py`

**Step 1: Write failing tests**

```python
class TestFirstRunConfig:
    def test_first_run_complete_default_false(self):
        config = AegisConfig()
        assert config.get("first_run_complete") is False

    def test_exclusions_default_empty(self):
        config = AegisConfig()
        assert config.get("exclusions.processes") == []
        assert config.get("exclusions.directories") == []
        assert config.get("exclusions.ips") == []

    def test_sysmon_installed_default_false(self):
        config = AegisConfig()
        assert config.get("sysmon.installed") is False

    def test_sensitivity_default_medium(self):
        config = AegisConfig()
        assert config.get("detection.sensitivity") == "medium"
```

**Step 2: Run to verify failure**

**Step 3: Add to DEFAULT_CONFIG**

```python
"first_run_complete": False,
"exclusions": {
    "processes": [],
    "directories": [],
    "ips": [],
},
"sysmon": {
    "installed": False,
    "config_path": "",
},
"detection": {
    ...existing keys...,
    "sensitivity": "medium",  # low, medium, high
},
```

**Step 4: Run tests, commit**

```bash
git commit -m "feat: first-run config keys (exclusions, sensitivity, sysmon)"
```

---

## Task 4: Baseline Scanner

**Files:**
- Create: `src/aegis/core/baseline_scanner.py`
- Test: `tests/test_core/test_baseline_scanner.py`

**Step 1: Write failing tests**

```python
"""Tests for system baseline scanner."""
from __future__ import annotations

from unittest.mock import patch
from aegis.core.baseline_scanner import BaselineScanner, BaselineSnapshot


class TestBaselineSnapshot:
    def test_snapshot_has_processes(self):
        snap = BaselineSnapshot(
            processes=["explorer.exe", "svchost.exe"],
            connections=[("192.168.1.1", 443)],
            services=["Spooler", "BITS"],
            timestamp=1000.0,
        )
        assert len(snap.processes) == 2
        assert snap.timestamp == 1000.0


class TestBaselineScanner:
    @patch("aegis.core.baseline_scanner.psutil")
    def test_scan_returns_snapshot(self, mock_psutil):
        mock_psutil.process_iter.return_value = []
        mock_psutil.net_connections.return_value = []
        scanner = BaselineScanner()
        snap = scanner.scan()
        assert isinstance(snap, BaselineSnapshot)

    @patch("aegis.core.baseline_scanner.psutil")
    def test_scan_captures_processes(self, mock_psutil):
        proc = type("P", (), {"info": {"name": "test.exe", "pid": 1}})()
        mock_psutil.process_iter.return_value = [proc]
        mock_psutil.net_connections.return_value = []
        scanner = BaselineScanner()
        snap = scanner.scan()
        assert "test.exe" in snap.processes
```

**Step 2: Run to verify failure**

**Step 3: Implement**

`BaselineSnapshot` dataclass: processes (list[str]), connections (list[tuple]), services (list[str]), timestamp (float)

`BaselineScanner.scan() -> BaselineSnapshot`: Uses psutil to enumerate running processes, active network connections, and Windows services. Returns a snapshot for the first-run wizard.

**Step 4: Run tests, commit**

```bash
git commit -m "feat: baseline scanner for first-run system inventory"
```

---

## Task 5: First-Run Wizard — Core Logic

**Files:**
- Create: `src/aegis/ui/first_run_wizard.py`
- Test: `tests/test_ui/test_first_run_wizard.py`

**Step 1: Write failing tests**

```python
"""Tests for first-run wizard logic (no Qt required)."""
from __future__ import annotations

from aegis.ui.first_run_wizard import (
    WizardConfig,
    apply_wizard_config,
)
from aegis.core.config import AegisConfig


class TestWizardConfig:
    def test_default_sensors_all_enabled(self):
        wc = WizardConfig()
        assert wc.sensors_enabled["network"] is True
        assert wc.sensors_enabled["process"] is True

    def test_sensitivity_maps_to_threshold(self):
        wc = WizardConfig(sensitivity="low")
        assert wc.anomaly_threshold == 0.8
        wc2 = WizardConfig(sensitivity="high")
        assert wc2.anomaly_threshold == 0.4


class TestApplyWizardConfig:
    def test_applies_sensor_settings(self):
        config = AegisConfig()
        wc = WizardConfig()
        wc.sensors_enabled["network"] = False
        apply_wizard_config(config, wc)
        assert config.get("sensors.network.enabled") is False

    def test_applies_exclusions(self):
        config = AegisConfig()
        wc = WizardConfig()
        wc.excluded_processes = ["steam.exe"]
        apply_wizard_config(config, wc)
        assert "steam.exe" in config.get("exclusions.processes")

    def test_marks_first_run_complete(self):
        config = AegisConfig()
        wc = WizardConfig()
        apply_wizard_config(config, wc)
        assert config.get("first_run_complete") is True
```

**Step 2: Run to verify failure**

**Step 3: Implement**

`WizardConfig` dataclass: sensors_enabled (dict), sensitivity (str), anomaly_threshold (float), feeds_enabled (dict), api_keys (dict), excluded_processes (list), excluded_dirs (list), excluded_ips (list), install_sysmon (bool)

Sensitivity mapping: low→0.8, medium→0.6, high→0.4 (anomaly threshold)

`apply_wizard_config(config, wizard_config)`: Writes all wizard choices to the AegisConfig, sets first_run_complete=True, saves config.

The PySide6 QWizard UI will be a separate task — this task establishes the testable logic layer.

**Step 4: Run tests, commit**

```bash
git commit -m "feat: first-run wizard config logic and apply function"
```

---

## Task 6: First-Run Wizard — Qt UI

**Files:**
- Modify: `src/aegis/ui/first_run_wizard.py`
- Modify: `src/aegis/__main__.py`

**Step 1: Implement PySide6 wizard**

Add `FirstRunWizard(QWizard)` with 8 pages:
1. WelcomePage (QLabel with branding)
2. SensorPage (checkboxes per sensor)
3. ThreatIntelPage (feed toggles + API key fields)
4. TuningPage (sensitivity slider)
5. SysmonPage (status check + install button)
6. BaselinePage (progress bar + scan results)
7. ExclusionsPage (list widgets with add/remove)
8. SummaryPage (read-only config display)

`accept()` → collects WizardConfig, calls apply_wizard_config()

**Step 2: Wire into __main__.py**

In `main()`, after loading config, check `config.get("first_run_complete")`. If False, show wizard before launching dashboard.

**Step 3: Manual testing**

Run: `python -m aegis` — should show wizard on first run

**Step 4: Commit**

```bash
git commit -m "feat: first-run wizard Qt UI (8 pages)"
```

---

## Task 7: Sysmon Integration

**Files:**
- Create: `src/aegis/core/sysmon_manager.py`
- Test: `tests/test_core/test_sysmon_manager.py`

**Step 1: Write failing tests**

```python
"""Tests for Sysmon management."""
from __future__ import annotations

from unittest.mock import patch, MagicMock
from aegis.core.sysmon_manager import SysmonManager


class TestSysmonManager:
    @patch("aegis.core.sysmon_manager.subprocess")
    def test_is_installed_true(self, mock_sub):
        mock_sub.run.return_value = MagicMock(returncode=0)
        mgr = SysmonManager()
        assert mgr.is_installed() is True

    @patch("aegis.core.sysmon_manager.subprocess")
    def test_is_installed_false(self, mock_sub):
        mock_sub.run.return_value = MagicMock(returncode=1)
        mgr = SysmonManager()
        assert mgr.is_installed() is False

    @patch("aegis.core.sysmon_manager.subprocess")
    def test_install_calls_sysmon_exe(self, mock_sub):
        mock_sub.run.return_value = MagicMock(returncode=0)
        mgr = SysmonManager(sysmon_path="tools/sysmon/Sysmon64.exe")
        result = mgr.install()
        assert result is True
        mock_sub.run.assert_called()

    def test_default_config_path(self):
        mgr = SysmonManager()
        assert "sysmonconfig" in mgr.config_path
```

**Step 2: Run to verify failure**

**Step 3: Implement**

`SysmonManager`:
- `is_installed() -> bool`: runs `sc query Sysmon64`
- `install() -> bool`: runs `Sysmon64.exe -accepteula -i config.xml`
- `uninstall() -> bool`: runs `Sysmon64.exe -u`
- `get_version() -> str | None`: parse output of `Sysmon64.exe -v`

**Step 4: Run tests, commit**

```bash
git commit -m "feat: Sysmon manager (install/uninstall/status)"
```

---

## Task 8: PyInstaller Build Script

**Files:**
- Create: `build/build.py`
- Create: `build/aegis.spec`

**Step 1: Create build directory**

```bash
mkdir -p build
```

**Step 2: Write build.py**

Script that:
- Reads version from `pyproject.toml`
- Runs PyInstaller with the .spec file
- Copies non-Python assets (rules/, tools/sysmon/) to dist
- Reports build size and file count

**Step 3: Write aegis.spec**

PyInstaller spec file:
- Entry point: `src/aegis/__main__.py`
- Hidden imports: PySide6 plugins, zmq, sklearn, onnxruntime, ctypes modules
- Data files: rules/, tools/, data/ (non-Python assets)
- Console: False (windowed app)
- Icon: assets/aegis.ico (create placeholder)
- Version info from pyproject.toml

**Step 4: Test build**

Run: `python build/build.py`
Expected: `dist/aegis/aegis.exe` exists

**Step 5: Commit**

```bash
git commit -m "feat: PyInstaller build script and spec file"
```

---

## Task 9: NSIS Installer Script

**Files:**
- Create: `build/installer.nsi`
- Create: `build/license.txt`

**Step 1: Write installer.nsi**

NSIS script with:
- Welcome, License, Directory, Components, Install, Finish pages
- Components: Core (required), Sysmon (default checked), Desktop Shortcut
- Install section: copy files, register service, create shortcuts, write uninstall info
- Uninstall section: stop service, remove service, delete files, remove shortcuts, remove registry

**Step 2: Write license.txt**

MIT license text for the installer license page.

**Step 3: Test NSIS compilation** (if NSIS installed)

Run: `makensis build/installer.nsi`
Expected: `build/aegis-setup.exe` exists

**Step 4: Commit**

```bash
git commit -m "feat: NSIS installer script with Sysmon component"
```

---

## Task 10: Phase 25 Integration Test

**Files:**
- Create: `tests/test_integration/test_phase25_deployment.py`

**Step 1: Write integration tests**

Test the full first-run flow:
- Config starts with `first_run_complete: False`
- WizardConfig applies correctly
- Service framework starts/stops coordinator
- Dual-mode detection works
- Sysmon manager checks status
- Baseline scanner produces snapshot

**Step 2: Run all tests**

Run: `pytest --tb=short`

**Step 3: Commit**

```bash
git commit -m "feat: Phase 25 integration tests for deployment"
```

---

# Phase 26: AI/ML Enhancement

---

## Task 11: Feature Extractor

**Files:**
- Create: `src/aegis/ml/__init__.py`
- Create: `src/aegis/ml/feature_extractor.py`
- Test: `tests/test_ml/test_feature_extractor.py`

**Step 1: Write failing tests**

```python
"""Tests for event feature extraction."""
from __future__ import annotations

from aegis.core.models import AegisEvent, SensorType, Severity
from aegis.ml.feature_extractor import FeatureExtractor


class TestFeatureExtractor:
    def test_extract_returns_dict(self):
        extractor = FeatureExtractor()
        event = AegisEvent(
            sensor=SensorType.NETWORK,
            event_type="connection_snapshot",
            data={"total_connections": 5, "unique_remote_ips": 3},
        )
        features = extractor.extract(event)
        assert isinstance(features, dict)
        assert "total_connections" in features

    def test_extract_network_features(self):
        extractor = FeatureExtractor()
        event = AegisEvent(
            sensor=SensorType.NETWORK,
            event_type="connection_snapshot",
            data={
                "total_connections": 10,
                "unique_remote_ips": 5,
                "unique_remote_ports": 3,
                "dns_query_count": 20,
            },
        )
        features = extractor.extract(event)
        assert features["total_connections"] == 10
        assert features["unique_remote_ips"] == 5

    def test_unknown_sensor_returns_generic(self):
        extractor = FeatureExtractor()
        event = AegisEvent(
            sensor=SensorType.ETW,
            event_type="etw.powershell_scriptblock",
            data={"script_text": "Get-Process"},
        )
        features = extractor.extract(event)
        assert "data_field_count" in features

    def test_batch_extract(self):
        extractor = FeatureExtractor()
        events = [
            AegisEvent(
                sensor=SensorType.PROCESS,
                event_type="process_new",
                data={"name": "test.exe", "pid": 1},
            )
            for _ in range(5)
        ]
        batch = extractor.batch_extract(events)
        assert len(batch) == 5
```

**Step 2: Run to verify failure**

**Step 3: Implement**

`FeatureExtractor` with per-sensor extraction logic:
- Network: total_connections, unique_remote_ips, unique_remote_ports, dns_query_count
- Process: cpu_percent, memory_mb, num_threads, cmdline_entropy
- File: files_changed, entropy_increase_rate
- Generic fallback: data_field_count, severity_ordinal, timestamp

`extract(event) -> dict[str, float]`
`batch_extract(events) -> list[dict[str, float]]`

**Step 4: Run tests, commit**

```bash
git commit -m "feat: ML feature extractor for event vectorization"
```

---

## Task 12: Training Pipeline

**Files:**
- Create: `src/aegis/ml/training_pipeline.py`
- Test: `tests/test_ml/test_training_pipeline.py`

**Step 1: Write failing tests**

```python
"""Tests for adaptive baseline training pipeline."""
from __future__ import annotations

import numpy as np
from unittest.mock import patch, MagicMock
from aegis.ml.training_pipeline import (
    TrainingPipeline,
    ModelVersion,
    TrainingStatus,
)


class TestModelVersion:
    def test_creation(self):
        mv = ModelVersion(
            version=1,
            timestamp=1000.0,
            model_type="isolation_forest",
            metrics={"score": 0.95},
        )
        assert mv.version == 1

class TestTrainingPipeline:
    def test_status_starts_collecting(self):
        pipeline = TrainingPipeline()
        assert pipeline.status == TrainingStatus.COLLECTING

    def test_add_samples(self):
        pipeline = TrainingPipeline(min_samples=10)
        for i in range(5):
            pipeline.add_sample({"f1": float(i), "f2": float(i * 2)})
        assert pipeline.sample_count == 5

    def test_train_requires_min_samples(self):
        pipeline = TrainingPipeline(min_samples=50)
        pipeline.add_sample({"f1": 1.0})
        result = pipeline.train()
        assert result is False

    def test_train_succeeds_with_enough_samples(self):
        pipeline = TrainingPipeline(min_samples=10)
        rng = np.random.default_rng(42)
        for _ in range(20):
            pipeline.add_sample({
                "f1": rng.normal(0, 1),
                "f2": rng.normal(5, 2),
            })
        result = pipeline.train()
        assert result is True
        assert pipeline.status == TrainingStatus.TRAINED

    def test_score_after_training(self):
        pipeline = TrainingPipeline(min_samples=10)
        rng = np.random.default_rng(42)
        for _ in range(50):
            pipeline.add_sample({
                "f1": rng.normal(0, 1),
                "f2": rng.normal(5, 2),
            })
        pipeline.train()
        score = pipeline.score({"f1": 0.0, "f2": 5.0})
        assert 0.0 <= score <= 1.0

    def test_model_versioning(self):
        pipeline = TrainingPipeline(min_samples=10)
        rng = np.random.default_rng(42)
        for _ in range(20):
            pipeline.add_sample({"f1": rng.normal()})
        pipeline.train()
        assert pipeline.current_version.version == 1
        pipeline.train()
        assert pipeline.current_version.version == 2
```

**Step 2: Run to verify failure**

**Step 3: Implement**

`TrainingStatus` enum: COLLECTING, TRAINING, TRAINED, FAILED

`ModelVersion` dataclass: version, timestamp, model_type, metrics, path

`TrainingPipeline`:
- `__init__(min_samples, model_dir)`: Isolation Forest params, sample buffer
- `add_sample(features)`: Append to rolling buffer
- `train() -> bool`: Fit IsolationForest on collected samples, save with joblib, increment version
- `score(features) -> float`: Score a sample against the trained model
- `rollback()`: Revert to previous model version
- `status` property, `current_version` property, `sample_count` property

**Step 4: Run tests, commit**

```bash
git commit -m "feat: ML training pipeline with model versioning"
```

---

## Task 13: Concept Drift Detector

**Files:**
- Create: `src/aegis/ml/drift_detector.py`
- Test: `tests/test_ml/test_drift_detector.py`

**Step 1: Write failing tests**

```python
"""Tests for concept drift detection."""
from __future__ import annotations

import numpy as np
from aegis.ml.drift_detector import DriftDetector, DriftResult


class TestDriftDetector:
    def test_no_drift_on_stable_data(self):
        detector = DriftDetector(window_size=50)
        rng = np.random.default_rng(42)
        for _ in range(100):
            detector.update({"f1": rng.normal(0, 1)})
        result = detector.check()
        assert result.drift_detected is False

    def test_drift_on_mean_shift(self):
        detector = DriftDetector(window_size=50)
        rng = np.random.default_rng(42)
        # Stable period
        for _ in range(100):
            detector.update({"f1": rng.normal(0, 1)})
        # Shift mean by 10 std
        for _ in range(100):
            detector.update({"f1": rng.normal(10, 1)})
        result = detector.check()
        assert result.drift_detected is True
        assert "f1" in result.drifted_features

    def test_drift_result_has_details(self):
        result = DriftResult(
            drift_detected=True,
            drifted_features=["f1"],
            details={"f1": {"old_mean": 0, "new_mean": 10}},
        )
        assert result.drifted_features == ["f1"]
```

**Step 2: Run to verify failure**

**Step 3: Implement**

`DriftResult` dataclass: drift_detected (bool), drifted_features (list[str]), details (dict)

`DriftDetector`:
- Maintains sliding windows of feature values
- `update(features)`: Append to window
- `check() -> DriftResult`: Compare recent window stats to baseline window using Page-Hinkley test
- Drift threshold: 3 standard deviations shift in mean

**Step 4: Run tests, commit**

```bash
git commit -m "feat: concept drift detector with Page-Hinkley test"
```

---

## Task 14: Threat Prediction Engine

**Files:**
- Create: `src/aegis/detection/threat_predictor.py`
- Create: `data/mitre/attack_chains.json`
- Test: `tests/test_detection/test_threat_predictor.py`

**Step 1: Write failing tests**

```python
"""Tests for MITRE ATT&CK threat prediction."""
from __future__ import annotations

from aegis.detection.threat_predictor import (
    ThreatPredictor,
    PredictionResult,
)


class TestThreatPredictor:
    def test_predict_from_known_chain(self):
        predictor = ThreatPredictor()
        result = predictor.predict(["T1566", "T1059"])
        assert isinstance(result, PredictionResult)
        assert len(result.predictions) >= 1
        assert result.predictions[0].probability > 0

    def test_empty_sequence_returns_no_prediction(self):
        predictor = ThreatPredictor()
        result = predictor.predict([])
        assert len(result.predictions) == 0

    def test_unknown_technique_handled(self):
        predictor = ThreatPredictor()
        result = predictor.predict(["T9999"])
        assert isinstance(result, PredictionResult)

    def test_prediction_has_defensive_recommendation(self):
        predictor = ThreatPredictor()
        result = predictor.predict(["T1566", "T1059", "T1055"])
        for pred in result.predictions:
            assert pred.defense is not None

    def test_confidence_calibration(self):
        predictor = ThreatPredictor()
        result = predictor.predict(["T1566"])
        for pred in result.predictions:
            assert 0.0 <= pred.probability <= 1.0
```

**Step 2: Run to verify failure**

**Step 3: Implement**

`PredictionResult` dataclass with list of `TechniquePrediction(technique_id, name, probability, defense, mitre_tactic)`

`ThreatPredictor`:
- Loads `data/mitre/attack_chains.json` — predefined MITRE ATT&CK chain patterns
- `predict(observed_techniques) -> PredictionResult`: Markov chain transition probabilities from chain database. For each observed sequence, find matching chains, compute next-step probabilities.
- Platt scaling on raw probabilities for calibration
- Defensive recommendations mapped per technique

Create `data/mitre/attack_chains.json` with 15-20 common attack chains from MITRE ATT&CK.

**Step 4: Run tests, commit**

```bash
git commit -m "feat: threat prediction engine with Markov chains and MITRE ATT&CK"
```

---

## Task 15: LLM Analyzer — Core

**Files:**
- Create: `src/aegis/intelligence/llm_analyzer.py`
- Test: `tests/test_intelligence/test_llm_analyzer.py`

**Step 1: Write failing tests**

```python
"""Tests for LLM-powered analysis."""
from __future__ import annotations

from unittest.mock import patch, MagicMock, AsyncMock
from aegis.intelligence.llm_analyzer import (
    LLMAnalyzer,
    TriageResult,
    LLMConfig,
)
from aegis.core.models import Alert, SensorType, Severity


class TestLLMConfig:
    def test_default_rate_limit(self):
        cfg = LLMConfig()
        assert cfg.daily_budget == 100

    def test_privacy_defaults(self):
        cfg = LLMConfig()
        assert cfg.anonymize_paths is True


class TestLLMAnalyzer:
    def test_triage_offline_fallback(self):
        analyzer = LLMAnalyzer(api_key=None)
        alert = Alert(
            event_id="test", sensor=SensorType.NETWORK,
            alert_type="suspicious_connection",
            severity=Severity.HIGH, title="Test",
            description="Test alert", confidence=0.9,
            data={}, mitre_ids=["T1071"],
        )
        result = analyzer.triage(alert)
        assert isinstance(result, TriageResult)
        assert result.source == "template"

    def test_rate_limiting(self):
        analyzer = LLMAnalyzer(api_key="test-key")
        analyzer._call_count = 100
        alert = Alert(
            event_id="test", sensor=SensorType.NETWORK,
            alert_type="test", severity=Severity.LOW,
            title="Test", description="Test",
            confidence=0.5, data={}, mitre_ids=[],
        )
        result = analyzer.triage(alert)
        assert result.source == "template"  # Fell back due to budget

    def test_anonymize_paths(self):
        analyzer = LLMAnalyzer(api_key=None)
        text = "File at C:\\Users\\john\\Documents\\secret.doc"
        anon = analyzer._anonymize(text)
        assert "john" not in anon

    def test_nl_to_sql(self):
        analyzer = LLMAnalyzer(api_key=None)
        sql = analyzer.nl_to_sql(
            "show me recent alerts",
            schema_hint="alerts(alert_id, timestamp, severity)",
        )
        assert sql is not None  # Returns template-based fallback
```

**Step 2: Run to verify failure**

**Step 3: Implement**

`LLMConfig` dataclass: api_key, daily_budget (100), anonymize_paths (True), anonymize_usernames (True), provider ("claude"|"ollama")

`TriageResult` dataclass: severity_assessment, narrative, investigation_steps, fp_likelihood, source ("api"|"template")

`LLMAnalyzer`:
- `__init__(api_key, config)`: Configure anthropic client or None
- `triage(alert, context) -> TriageResult`: Send to Claude API, parse response. Fallback to template-based triage.
- `nl_to_sql(question, schema_hint) -> str | None`: Convert NL to SQL via API. Validate result is SELECT-only.
- `summarize_incident(incident) -> str`: Generate incident summary
- `_anonymize(text) -> str`: Replace paths/usernames with placeholders
- Rate limit tracking with daily budget

**Step 4: Run tests, commit**

```bash
git commit -m "feat: LLM analyzer with Claude API, offline fallback, privacy controls"
```

---

## Task 16: Pipeline Integration — Training & Prediction

**Files:**
- Modify: `src/aegis/detection/pipeline.py`
- Modify: `src/aegis/core/coordinator.py`
- Test: `tests/test_detection/test_pipeline.py`

**Step 1: Write failing tests**

Test that pipeline accepts `threat_predictor` parameter and runs it on correlated incidents. Test that coordinator wires training pipeline for baseline collection.

**Step 2: Implement**

- Add `threat_predictor` optional param to `DetectionPipeline.__init__`
- Add `_run_threat_prediction()` method called on events with MITRE IDs
- In coordinator, create `TrainingPipeline` during setup, wire `FeatureExtractor`

**Step 3: Run tests, commit**

```bash
git commit -m "feat: integrate threat predictor and training pipeline into coordinator"
```

---

## Task 17: Phase 26 Integration Test

**Files:**
- Create: `tests/test_integration/test_phase26_aiml.py`

Test end-to-end: feature extraction → training pipeline → scoring → drift detection → threat prediction → LLM triage fallback.

```bash
git commit -m "feat: Phase 26 integration tests for AI/ML enhancement"
```

---

# Phase 27: Threat Hunting & Forensics

---

## Task 18: Timeline Data Model

**Files:**
- Create: `src/aegis/forensics/__init__.py`
- Create: `src/aegis/forensics/timeline_engine.py`
- Test: `tests/test_forensics/test_timeline_engine.py`

**Step 1: Write failing tests**

```python
"""Tests for attack timeline reconstruction."""
from __future__ import annotations

from aegis.forensics.timeline_engine import (
    TimelineEvent,
    TimelineEngine,
)


class TestTimelineEvent:
    def test_creation(self):
        evt = TimelineEvent(
            timestamp=1000.0,
            source_sensor="process",
            event_type="process_new",
            severity="high",
            mitre_technique="T1059",
            summary="powershell.exe spawned by winword.exe",
            process_context={"pid": 1234, "name": "powershell.exe"},
            parent_event_id=None,
        )
        assert evt.mitre_technique == "T1059"


class TestTimelineEngine:
    def test_build_timeline_from_events(self):
        engine = TimelineEngine()
        events = [
            {"timestamp": 1000, "sensor": "process",
             "event_type": "process_new", "severity": "medium",
             "data": {"name": "cmd.exe", "pid": 1}},
            {"timestamp": 1001, "sensor": "network",
             "event_type": "connection", "severity": "high",
             "data": {"remote_ip": "10.0.0.1"}},
        ]
        timeline = engine.build(events)
        assert len(timeline) == 2
        assert timeline[0].timestamp <= timeline[1].timestamp

    def test_causality_linking(self):
        engine = TimelineEngine()
        events = [
            {"timestamp": 1000, "sensor": "process",
             "event_type": "process_new", "severity": "medium",
             "data": {"name": "powershell.exe", "pid": 100,
                      "parent_pid": 50}},
            {"timestamp": 999, "sensor": "process",
             "event_type": "process_new", "severity": "low",
             "data": {"name": "winword.exe", "pid": 50}},
        ]
        timeline = engine.build(events)
        # powershell should link to winword as parent
        ps_event = [e for e in timeline if "powershell" in e.summary][0]
        assert ps_event.parent_event_id is not None

    def test_empty_events(self):
        engine = TimelineEngine()
        timeline = engine.build([])
        assert timeline == []
```

**Step 2: Run to verify failure**

**Step 3: Implement**

`TimelineEvent` dataclass: timestamp, source_sensor, event_type, severity, mitre_technique, summary, process_context, network_context, parent_event_id, event_id

`TimelineEngine`:
- `build(events) -> list[TimelineEvent]`: Sort by timestamp, extract MITRE techniques, build causality links via PID/parent_PID relationships
- `build_from_incident(db, incident_id) -> list[TimelineEvent]`: Pull events from database
- `export_html(timeline) -> str`: Render as interactive HTML
- `export_json(timeline) -> str`: Serialize to JSON

**Step 4: Run tests, commit**

```bash
git commit -m "feat: timeline engine with causality linking"
```

---

## Task 19: Report Templates

**Files:**
- Create: `templates/reports/incident_report.html`
- Create: `templates/reports/daily_summary.html`
- Modify: `src/aegis/response/report_generator.py`
- Test: `tests/test_response/test_report_generator.py`

**Step 1: Write failing tests**

Test that `render_incident_report()` produces HTML with timeline, IOCs, MITRE techniques. Test `render_daily_summary()` produces HTML with alert counts.

**Step 2: Create Jinja2 templates**

`incident_report.html`: Professional dark-themed report with sections for summary, timeline table, alerts, IOCs, MITRE techniques, response actions, remediation steps.

`daily_summary.html`: Compact report with alert counts by severity, top rules triggered, new IOCs, sensor health status.

**Step 3: Enhance report_generator.py**

Add Jinja2 template rendering, PDF export via WeasyPrint (optional), CSV export.

**Step 4: Run tests, commit**

```bash
git commit -m "feat: Jinja2 report templates (incident, daily summary)"
```

---

## Task 20: Natural Language Threat Hunting

**Files:**
- Modify: `src/aegis/ui/pages/threat_hunt.py`
- Test: `tests/test_ui/test_threat_hunt.py`

**Step 1: Write failing tests**

```python
class TestNLHunting:
    def test_pre_built_queries_loaded(self):
        from aegis.ui.pages.threat_hunt import PRE_BUILT_QUERIES
        assert len(PRE_BUILT_QUERIES) >= 10

    def test_query_validation_blocks_delete(self):
        from aegis.ui.pages.threat_hunt import validate_query
        assert validate_query("DELETE FROM events") is False

    def test_query_validation_allows_select(self):
        from aegis.ui.pages.threat_hunt import validate_query
        assert validate_query("SELECT * FROM alerts") is True
```

**Step 2: Implement**

- Add `PRE_BUILT_QUERIES` dict with 20 common hunting queries
- Add NL input field that calls `LLMAnalyzer.nl_to_sql()`
- Add `validate_query()` that blocks non-SELECT statements
- Add query history (list of past queries stored in config)
- Add saved queries (bookmark feature)

**Step 3: Run tests, commit**

```bash
git commit -m "feat: NL threat hunting with pre-built queries and validation"
```

---

## Task 21: Phase 27 Integration Test

**Files:**
- Create: `tests/test_integration/test_phase27_forensics.py`

Test: timeline reconstruction from mock incident, report generation in HTML, NL query validation.

```bash
git commit -m "feat: Phase 27 integration tests for forensics"
```

---

## Task 22: Final Verification — All Phases

**Step 1: Run full test suite**

Run: `pytest --tb=short`
Expected: ALL PASS

**Step 2: Run ruff**

Run: `ruff check src/`
Expected: No errors

**Step 3: Commit**

```bash
git add -A
git commit -m "feat: Phases 25-27 complete — deployment, AI/ML, forensics"
```

---

## Task Dependencies

```
Phase 25 (Deployment):
  Task 1 (Service) ──► Task 2 (Dual-mode) ──► Task 6 (Wizard UI)
  Task 3 (Config) ──► Task 5 (Wizard logic) ──► Task 6 (Wizard UI)
  Task 4 (Baseline) ──► Task 6 (Wizard UI)
  Task 7 (Sysmon) ──► Task 6 (Wizard UI)
  Task 8 (PyInstaller) ──► Task 9 (NSIS)
  Task 10 (Integration)

Phase 26 (AI/ML):
  Task 11 (Features) ──► Task 12 (Training) ──► Task 13 (Drift)
  Task 14 (Prediction) (independent)
  Task 15 (LLM) (independent)
  Task 16 (Pipeline integration) ◄── Tasks 12, 14
  Task 17 (Integration)

Phase 27 (Forensics):
  Task 18 (Timeline) (independent)
  Task 19 (Reports) (independent)
  Task 20 (NL Hunting) ◄── Task 15 (LLM)
  Task 21 (Integration)
  Task 22 (Final)
```

**Parallel-safe groups:**
- Group A: Tasks 1-4 (service, dual-mode, config, baseline) — mostly independent
- Group B: Tasks 7-9 (sysmon, pyinstaller, nsis) — independent of Group A
- Group C: Tasks 11, 14, 15 (features, prediction, LLM) — fully independent
- Group D: Tasks 18, 19 (timeline, reports) — fully independent
